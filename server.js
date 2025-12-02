require('dotenv').config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const ethUtil = require("ethereumjs-util");

const app = express();
app.use(cors());
app.use(express.json());

// ===== MongoDB Connection =====
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB connected"))
  .catch(err => console.error("MongoDB Error:", err));


// ===== User Schema (Multiple Wallets) =====
const userSchema = new mongoose.Schema({
  wallets: { type: [String], default: [] },
  nonce: { type: String, default: () => Math.floor(Math.random() * 1000000).toString() }
});

const User = mongoose.model("User", userSchema);


// ==========================================================
// =============== REQUEST NONCE (LOGIN STEP 1) ==============
// ==========================================================
app.post("/auth/request-nonce", async (req, res) => {
  try {
    const { wallet } = req.body;
    if (!wallet) return res.status(400).json({ error: "Wallet address required" });

    let user = await User.findOne({ wallets: wallet.toLowerCase() });

    // If user does NOT exist --> create new user with FIRST wallet
    if (!user) {
      user = new User({
        wallets: [wallet.toLowerCase()],
        nonce: Math.floor(Math.random() * 1_000_000).toString()
      });
      await user.save();
    }

    // Always refresh nonce on login request
    user.nonce = Math.floor(Math.random() * 1_000_000).toString();
    await user.save();

    res.json({ nonce: user.nonce });

  } catch (err) {
    console.error("Nonce Error:", err);
    res.status(500).json({ error: "Server error requesting nonce" });
  }
});


// ==========================================================
// ================= VERIFY SIGNATURE (LOGIN) ===============
// ==========================================================
app.post("/auth/verify", async (req, res) => {
  try {
    const { wallet, signature } = req.body;

    let user = await User.findOne({ wallets: wallet.toLowerCase() });
    if (!user) return res.status(400).json({ error: "User not found" });

    const msg = `Nonce: ${user.nonce}`;
    const msgHex = ethUtil.bufferToHex(Buffer.from(msg, 'utf8'));
    const msgBuffer = ethUtil.toBuffer(msgHex);
    const msgHash = ethUtil.hashPersonalMessage(msgBuffer);
    const sigBuffer = ethUtil.toBuffer(signature);
    const sigParams = ethUtil.fromRpcSig(sigBuffer);
    const pubKey = ethUtil.ecrecover(msgHash, sigParams.v, sigParams.r, sigParams.s);
    const addrBuf = ethUtil.pubToAddress(pubKey);
    const recoveredAddress = ethUtil.bufferToHex(addrBuf);

    if (recoveredAddress.toLowerCase() !== wallet.toLowerCase()) {
      return res.status(401).json({ error: "Signature verification failed" });
    }

    // Login successful → new nonce
    user.nonce = Math.floor(Math.random() * 1_000_000).toString();
    await user.save();

    const token = jwt.sign(
      { id: user._id, wallets: user.wallets },
      process.env.JWT_SECRET,
      { expiresIn: "1d" }
    );

    res.json({ token });

  } catch (err) {
    console.error("Verify Error:", err);
    res.status(500).json({ error: "Server error verifying signature" });
  }
});


// ==========================================================
// ========== ADD ADDITIONAL WALLET TO SAME USER ============
// ==========================================================
app.post("/auth/add-wallet", async (req, res) => {
  try {
    const { userId, newWallet } = req.body;

    await User.updateOne(
      { _id: userId },
      { $addToSet: { wallets: newWallet.toLowerCase() } }
    );

    res.json({ success: true });

  } catch (err) {
    console.error("Add Wallet Error:", err);
    res.status(500).json({ error: "Failed to add wallet" });
  }
});


// ===== Server Start =====
app.listen(3000, () => console.log("Server running on port 3000"));
