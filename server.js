require('dotenv').config();
const jwt = require("jsonwebtoken");
const ethUtil = require("ethereumjs-util");

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');

const app = express();

// --- FIXED CORS ---
app.use(cors({
  origin: [
    "http://localhost:3000",
    "https://cms-frontend-one.vercel.app"   // ✅ put your frontend URL here
  ],
  methods: ["GET", "POST", "PUT", "DELETE"],
  allowedHeaders: ["Content-Type", "Authorization"],
  credentials: true,
}));

app.use(express.json());

// --- Environment Vars ---
const MONGO_URI = process.env.MONGO_URI;
const PORT = process.env.PORT || 5000;

if (!MONGO_URI) {
  console.error("❌ Missing MONGO_URI in .env");
  process.exit(1);
}

// --- Connect MongoDB ---
mongoose.connect(MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log("✅ MongoDB Connected"))
.catch(err => {
  console.error("❌ MongoDB Error:", err);
  process.exit(1);
});

// Auth middleware
function requireAuth(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ message: "No token" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ message: "Invalid token" });
  }
}

// --- Article Schema ---
const articleSchema = new mongoose.Schema({
  title: String,
  content: String,
  createdAt: { type: Date, default: Date.now }
});
const Article = mongoose.model("Article", articleSchema);

// --- MetaMask User Schema ---
const userSchema = new mongoose.Schema({
  wallet: { type: String, unique: true },
  nonce: { type: String, default: () => Math.floor(Math.random() * 1000000).toString() }
});

const User = mongoose.model("User", userSchema);

// Helper
const isValidObjectId = id => mongoose.Types.ObjectId.isValid(id);

/* ===========================================================
    FIXED METAMASK AUTH (Option A)
   =========================================================== */

// Request nonce
app.post("/auth/request-nonce", async (req, res) => {
  try {
    const wallet = req.body.wallet?.toLowerCase();
    if (!wallet) return res.status(400).json({ message: "Wallet address required" });

    let user = await User.findOne({ wallet });

    if (!user) {
      user = await User.create({ wallet });
    } else {
      user.nonce = Math.floor(Math.random() * 1000000).toString();
      await user.save();
    }

    res.json({ wallet, nonce: user.nonce });
  } catch (err) {
    res.status(500).json({ message: "Server error requesting nonce" });
  }
});

// Verify signature
app.post("/auth/verify", async (req, res) => {
  try {
    const wallet = req.body.wallet?.toLowerCase();
    const signature = req.body.signature;

    if (!wallet || !signature)
      return res.status(400).json({ message: "Wallet and signature required" });

    const user = await User.findOne({ wallet });
    if (!user)
      return res.status(404).json({ message: "User not found" });

    const message = `Login nonce: ${user.nonce}`;
    const msgBuffer = Buffer.from(message);
    const msgHash = ethUtil.hashPersonalMessage(msgBuffer);

    const sig = ethUtil.fromRpcSig(signature);
    const publicKey = ethUtil.ecrecover(msgHash, sig.v, sig.r, sig.s);
    const recoveredWallet = ethUtil.bufferToHex(ethUtil.pubToAddress(publicKey));

    if (recoveredWallet.toLowerCase() !== wallet.toLowerCase()) {
      return res.status(401).json({ message: "Signature verification failed" });
    }

    // Update nonce after login
    user.nonce = Math.floor(Math.random() * 1000000).toString();
    await user.save();

    const token = jwt.sign(
      { wallet },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({ message: "Login success", token, wallet });
  } catch (err) {
    res.status(500).json({ message: "Server error verifying signature" });
  }
});

/* ===========================================================
    ARTICLES API
   =========================================================== */

app.get("/api/articles", async (req, res) => {
  try {
    const articles = await Article.find().sort({ createdAt: -1 });
    res.json(articles);
  } catch {
    res.status(500).json({ message: "Error fetching articles" });
  }
});

app.get("/api/articles/search", async (req, res) => {
  try {
    const q = req.query.q || "";
    const results = await Article.find({
      $or: [
        { title: { $regex: q, $options: "i" }},
        { content: { $regex: q, $options: "i" }}
      ]
    });
    res.json(results);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get one
app.get("/api/articles/:id", async (req, res) => {
  if (!isValidObjectId(req.params.id))
    return res.status(400).json({ message: "Invalid ID" });

  try {
    const a = await Article.findById(req.params.id);
    if (!a) return res.status(404).json({ message: "Not found" });
    res.json(a);
  } catch {
    res.status(500).json({ message: "Error fetching article" });
  }
});

// Create
app.post("/api/articles", async (req, res) => {
  try {
    const newA = await Article.create(req.body);
    res.status(201).json(newA);
  } catch {
    res.status(500).json({ message: "Error creating article" });
  }
});

// Update
app.put("/api/articles/:id", async (req, res) => {
  if (!isValidObjectId(req.params.id))
    return res.status(400).json({ message: "Invalid ID" });

  try {
    const updated = await Article.findByIdAndUpdate(
      req.params.id,
      req.body,
      { new: true }
    );
    res.json(updated);
  } catch {
    res.status(500).json({ message: "Error updating article" });
  }
});

// Delete
app.delete("/api/articles/:id", async (req, res) => {
  if (!isValidObjectId(req.params.id))
    return res.status(400).json({ message: "Invalid ID" });

  try {
    await Article.findByIdAndDelete(req.params.id);
    res.json({ message: "Deleted" });
  } catch {
    res.status(500).json({ message: "Error deleting article" });
  }
});

// Start server
app.listen(PORT, () =>
  console.log(`🚀 Server running on port ${PORT}`)
);
