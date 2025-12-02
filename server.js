// server.js
require("dotenv").config();
const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const { ethers } = require("ethers");

const app = express();

// ---------- CORS FIX ----------
app.use(cors({
  origin: [
    "http://localhost:3000",
    "https://cms-frontend-one.vercel.app"
  ],
  methods: ["GET", "POST"],
  allowedHeaders: ["Content-Type", "Authorization"],
  credentials: true
}));

app.use(express.json({ limit: "1mb" }));

// ---------- DATABASE ----------
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB Connected"))
  .catch(err => console.log(err));

const UserSchema = new mongoose.Schema({
  wallet: { type: String, unique: true },
  nonce: { type: String }
});

const User = mongoose.model("User", UserSchema);

// ---------- ROUTES ----------

// Request nonce
app.post("/auth/request-nonce", async (req, res) => {
  try {
    const { wallet } = req.body;
    if (!wallet) return res.status(400).json({ error: "Wallet required" });

    const nonce = Math.floor(Math.random() * 1000000).toString();

    let user = await User.findOne({ wallet });
    if (!user) {
      user = new User({ wallet, nonce });
    } else {
      user.nonce = nonce;
    }

    await user.save();
    res.json({ nonce });

  } catch (err) {
    console.log(err);
    res.status(500).json({ error: "Server error (nonce)" });
  }
});

// Verify signature
app.post("/auth/verify", async (req, res) => {
  try {
    const { wallet, signature } = req.body;

    const user = await User.findOne({ wallet });
    if (!user) return res.status(400).json({ error: "User not found" });

    const message = `Login nonce: ${user.nonce}`;
    const recovered = ethers.verifyMessage(message, signature);

    if (recovered.toLowerCase() !== wallet.toLowerCase()) {
      return res.status(400).json({ error: "Invalid signature" });
    }

    const token = jwt.sign(
      { wallet },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({ token });

  } catch (err) {
    console.log(err);
    res.status(500).json({ error: "Server error (verify)" });
  }
});

// ---------- START SERVER ----------
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log("Server running on port", PORT));
