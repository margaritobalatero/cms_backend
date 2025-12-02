require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const ethUtil = require("ethereumjs-util");

const app = express();
app.use(cors());
app.use(express.json());

// === Environment Variables ===
const MONGO_URI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET || "secret123";

// === Connect to MongoDB ===
mongoose.connect(MONGO_URI)
  .then(() => console.log("MongoDB connected"))
  .catch(err => console.error("MongoDB error:", err));

// === USER SCHEMA ===
// NOTE: username removed (this caused duplicate key errors)
const UserSchema = new mongoose.Schema({
  wallet: { type: String, required: true, unique: true },
  nonce: { type: String, required: true }
});

const User = mongoose.model("User", UserSchema);

// ========================================================================
//  AUTH: REQUEST NONCE
// ========================================================================
app.post("/auth/request-nonce", async (req, res) => {
  try {
    const wallet = (req.body.wallet || "").toLowerCase();

    if (!wallet) return res.status(400).json({ error: "Wallet required" });

    let user = await User.findOne({ wallet });

    if (!user) {
      // create brand-new user
      user = await User.create({
        wallet,
        nonce: Math.floor(Math.random() * 1000000).toString(),
      });
    } else {
      // update nonce
      user.nonce = Math.floor(Math.random() * 1000000).toString();
      await user.save();
    }

    return res.json({ nonce: user.nonce });

  } catch (err) {
    console.error("Error in /auth/request-nonce:", err);
    return res.status(500).json({ error: "Server error" });
  }
});

// ========================================================================
//  AUTH: VERIFY SIGNATURE
// ========================================================================
app.post("/auth/verify", async (req, res) => {
  try {
    const { wallet, signature } = req.body;

    if (!wallet || !signature)
      return res.status(400).json({ error: "Wallet and signature required" });

    const user = await User.findOne({ wallet });
    if (!user) return res.status(400).json({ error: "User not found" });

    const message = `Login nonce: ${user.nonce}`;
    const msgBuffer = Buffer.from(message, "utf8");
    const msgHash = ethUtil.hashPersonalMessage(msgBuffer);

    const signatureBuffer = ethUtil.toBuffer(signature);
    const signatureParams = ethUtil.fromRpcSig(signatureBuffer);

    const publicKey = ethUtil.ecrecover(
      msgHash,
      signatureParams.v,
      signatureParams.r,
      signatureParams.s
    );

    const recoveredAddress = ethUtil.bufferToHex(
      ethUtil.pubToAddress(publicKey)
    ).toLowerCase();

    if (recoveredAddress !== wallet.toLowerCase()) {
      return res.status(400).json({ error: "Signature invalid" });
    }

    // Create JWT
    const token = jwt.sign(
      { wallet: user.wallet, id: user._id },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    // Update nonce after successful login
    user.nonce = Math.floor(Math.random() * 1000000).toString();
    await user.save();

    return res.json({ token });

  } catch (err) {
    console.error("Error in /auth/verify:", err);
    return res.status(500).json({ error: "Server error" });
  }
});

// ========================================================================
//  START SERVER (Only for local testing)
// ========================================================================
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log("Legacy server listening...");
});
