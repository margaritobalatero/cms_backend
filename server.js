require('dotenv').config();
const jwt = require("jsonwebtoken");
const ethUtil = require("ethereumjs-util");
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

// --- Env ---
const MONGO_URI = process.env.MONGO_URI;
const PORT = process.env.PORT || 5000;

// --- Connect to MongoDB ---
if (!MONGO_URI) {
  console.error("❌ ERROR: MONGO_URI missing");
  process.exit(1);
}

mongoose.connect(MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('✅ MongoDB connected'))
.catch(err => {
  console.error('❌ MongoDB connection error:', err);
  process.exit(1);
});

// --- JWT middleware ---
function requireAuth(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ message: "No token" });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    res.status(401).json({ message: "Invalid token" });
  }
}

// --- User schema ---
const userSchema = new mongoose.Schema({
  wallet: { type: String, unique: true, required: true, lowercase: true },
  nonce: { type: String, default: () => Math.floor(Math.random() * 1000000).toString() }
});
const User = mongoose.model("User", userSchema);

// --- Article schema (optional) ---
const articleSchema = new mongoose.Schema({
  title: { type: String, required: true },
  content: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
});
const Article = mongoose.model('Article', articleSchema);

// --- Helper ---
const isValidObjectId = id => mongoose.Types.ObjectId.isValid(id);

// ==================== AUTH ====================

// Request nonce
app.post("/auth/request-nonce", async (req, res) => {
  try {
    let wallet = req.body.wallet;
    if (!wallet) return res.status(400).json({ message: "Wallet address required" });

    wallet = wallet.trim().toLowerCase(); // <-- TRIM + LOWERCASE

    let user = await User.findOne({ wallet });

    if (!user) {
      user = await User.create({ wallet });
    } else {
      user.nonce = Math.floor(Math.random() * 1000000).toString();
      await user.save();
    }

    res.json({ wallet, nonce: user.nonce });
  } catch (err) {
    console.error("❌ /auth/request-nonce ERROR:", err);
    res.status(500).json({ message: "Server error requesting nonce", error: err.message });
  }
});

// Verify signature
app.post("/auth/verify", async (req, res) => {
  try {
    let wallet = req.body.wallet;
    const signature = req.body.signature;

    if (!wallet || !signature) return res.status(400).json({ message: "Wallet and signature required" });

    wallet = wallet.trim().toLowerCase();

    const user = await User.findOne({ wallet });
    if (!user) return res.status(404).json({ message: "User not found" });

    const message = `Login nonce: ${user.nonce}`;
    const msgHash = ethUtil.hashPersonalMessage(Buffer.from(message));
    const sig = ethUtil.fromRpcSig(signature);
    const pubKey = ethUtil.ecrecover(msgHash, sig.v, sig.r, sig.s);
    const recoveredWallet = ethUtil.bufferToHex(ethUtil.pubToAddress(pubKey));

    if (recoveredWallet.toLowerCase() !== wallet) {
      return res.status(401).json({ message: "Signature verification failed" });
    }

    // Generate new nonce & save
    user.nonce = Math.floor(Math.random() * 1000000).toString();
    await user.save();

    // JWT token
    const token = jwt.sign({ wallet }, process.env.JWT_SECRET, { expiresIn: "7d" });

    res.json({ message: "Login success", token, wallet });
  } catch (err) {
    console.error("❌ /auth/verify ERROR:", err);
    res.status(500).json({ message: "Server error verifying signature", error: err.message });
  }
});

// ==================== Example Protected Route ====================
app.get("/api/secret", requireAuth, (req, res) => {
  res.json({ message: "You are logged in!", wallet: req.user.wallet });
});

// ==================== Start server ====================
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
