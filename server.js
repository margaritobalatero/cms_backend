// === Full server.js with MetaMask (Option A) merged ===

import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import { recoverPersonalSignature } from "@metamask/eth-sig-util";
import { bufferToHex } from "ethereumjs-util";

dotenv.config();

const app = express();
app.use(express.json());
app.use(cors());

// === MongoDB ===
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB connected"))
  .catch((err) => console.error(err));

// === User Schema ===
const userSchema = new mongoose.Schema({
  wallet: { type: String, unique: true },
  nonce: { type: String }
});
const User = mongoose.model("User", userSchema);

// === Generate random nonce ===
function generateNonce() {
  return Math.floor(Math.random() * 1000000).toString();
}

// === Request nonce ===
app.post("/auth/request-nonce", async (req, res) => {
  try {
    const { wallet } = req.body;
    if (!wallet) return res.status(400).json({ error: "Wallet missing" });

    let user = await User.findOne({ wallet });

    if (!user) {
      user = await User.create({ wallet, nonce: generateNonce() });
    } else {
      user.nonce = generateNonce();
      await user.save();
    }

    res.json({ nonce: user.nonce });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// === Verify signature ===
app.post("/auth/verify", async (req, res) => {
  try {
    const { wallet, signature } = req.body;
    const user = await User.findOne({ wallet });
    if (!user) return res.status(400).json({ error: "User not found" });

    const message = `Login nonce: ${user.nonce}`;
    const msgBufferHex = bufferToHex(Buffer.from(message, "utf8"));

    const recovered = recoverPersonalSignature({
      data: msgBufferHex,
      signature
    });

    if (recovered.toLowerCase() !== wallet.toLowerCase()) {
      return res.status(401).json({ error: "Signature mismatch" });
    }

    // Signature valid → create JWT
    const token = jwt.sign(
      { wallet },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    // regenerate nonce
    user.nonce = generateNonce();
    await user.save();

    res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// Protected route example
app.get("/profile", (req, res) => {
  try {
    const auth = req.headers.authorization;
    if (!auth) return res.status(401).json({ error: "Missing token" });

    const token = auth.replace("Bearer ", "");
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    res.json({ wallet: decoded.wallet });
  } catch (err) {
    res.status(401).json({ error: "Invalid token" });
  }
});

// === Start server ===
app.listen(5000, () => console.log("Server running on port 5000"));
