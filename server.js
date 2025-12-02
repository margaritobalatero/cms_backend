require("dotenv").config();
const jwt = require("jsonwebtoken");
const ethUtil = require("ethereumjs-util");

const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");

const app = express();
app.use(cors());
app.use(express.json());

// --- Environment Variables ---
const MONGO_URI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET || "supersecretjwtkey";

// --- MongoDB Connection ---
mongoose
  .connect(MONGO_URI)
  .then(() => console.log("MongoDB connected"))
  .catch((err) => console.error("MongoDB error:", err));

// --- User Schema ---
const userSchema = new mongoose.Schema({
  userId: { type: String, unique: true, required: true }, // Wallet address
  nonce: { type: Number, required: true },
});

const User = mongoose.model("User", userSchema);

// ============================================
//        REQUEST NONCE (LOGIN STEP 1)
// ============================================
app.post("/auth/request-nonce", async (req, res) => {
  try {
    const { userId } = req.body;

    if (!userId) {
      return res.status(400).json({ error: "userId is required" });
    }

    let user = await User.findOne({ userId });

    const newNonce = Math.floor(Math.random() * 1000000);

    if (!user) {
      // Create the user first time
      user = await User.create({ userId, nonce: newNonce });
    } else {
      // Update nonce every login attempt
      user.nonce = newNonce;
      await user.save();
    }

    return res.json({ userId: user.userId, nonce: user.nonce });
  } catch (err) {
    console.error("Error in /auth/request-nonce:", err);
    return res.status(500).json({ error: "Server error generating nonce" });
  }
});

// ============================================
//       VERIFY SIGNATURE (LOGIN STEP 2)
// ============================================
app.post("/auth/verify", async (req, res) => {
  try {
    const { userId, signature } = req.body;

    if (!userId || !signature) {
      return res.status(400).json({ error: "userId and signature required" });
    }

    const user = await User.findOne({ userId });
    if (!user) {
      return res.status(400).json({ error: "User not found" });
    }

    const message = `Login nonce: ${user.nonce}`;
    const msgBuffer = Buffer.from(message);
    const msgHash = ethUtil.hashPersonalMessage(msgBuffer);

    const signatureBuffer = ethUtil.toBuffer(signature);
    const sigParams = ethUtil.fromRpcSig(signatureBuffer);

    const publicKey = ethUtil.ecrecover(
      msgHash,
      sigParams.v,
      sigParams.r,
      sigParams.s
    );

    const addressBuffer = ethUtil.pubToAddress(publicKey);
    const recoveredAddress = ethUtil.bufferToHex(addressBuffer).toLowerCase();
    const normalizedUserId = userId.toLowerCase();

    if (recoveredAddress !== normalizedUserId) {
      return res.status(401).json({ error: "Signature verification failed" });
    }

    // Valid → Sign JWT
    const token = jwt.sign({ userId }, JWT_SECRET, { expiresIn: "7d" });

    return res.json({ token });
  } catch (err) {
    console.error("Error in /auth/verify:", err);
    return res.status(500).json({ error: "Server error verifying signature" });
  }
});

// ============================================
//               START SERVER
// ============================================
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
