require('dotenv').config(); // Load .env first
const jwt = require("jsonwebtoken");
const ethUtil = require("ethereumjs-util");

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

// --- Environment Variables ---
const MONGO_URI = process.env.MONGO_URI;
const PORT = process.env.PORT || 5000;

// --- Connect to MongoDB ---
if (!MONGO_URI) {
  console.error("❌ ERROR: MONGO_URI is missing from .env");
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
  title: { type: String, required: true },
  content: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
});

const Article = mongoose.model('Article', articleSchema);

// ===== User Schema for Multiple Wallets =====
const userSchema = new mongoose.Schema({
  wallets: {
    type: [String],  // array of wallet addresses
    required: true,
    validate: {
      validator: function(v) {
        return v.length > 0;
      },
      message: 'At least one wallet is required'
    }
  },
  nonce: { 
    type: String, 
    default: () => Math.floor(Math.random() * 1000000).toString() 
  }
});

const User = mongoose.model("User", userSchema);

// Helper
const isValidObjectId = id => mongoose.Types.ObjectId.isValid(id);

// ==================== ROUTES ====================

app.get("/api/secret", requireAuth, (req, res) => {
  res.json({ message: "You are logged in!", wallet: req.user.wallet });
});

// Get all articles
app.get('/api/articles', async (req, res) => {
  try {
    const articles = await Article.find().sort({ createdAt: -1 });
    res.json(articles);
  } catch (err) {
    res.status(500).json({ message: 'Server error fetching articles' });
  }
});

// Search articles
app.get('/api/articles/search', async (req, res) => {
  try {
    const q = req.query.q || "";
    const results = await Article.find({
      $or: [
        { title:   { $regex: q, $options: "i" }},
        { content: { $regex: q, $options: "i" }}
      ]
    });
    res.json(results);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get one article
app.get('/api/articles/:id', async (req, res) => {
  const { id } = req.params;
  if (!isValidObjectId(id)) return res.status(400).json({ message: 'Invalid article ID' });

  try {
    const article = await Article.findById(id);
    if (!article) return res.status(404).json({ message: 'Article not found' });
    res.json(article);
  } catch (err) {
    res.status(500).json({ message: 'Server error fetching article' });
  }
});

// Create article
app.post('/api/articles', async (req, res) => {
  const { title, content } = req.body;
  if (!title || !content)
    return res.status(400).json({ message: 'Title and content are required' });

  try {
    const article = new Article({ title, content });
    const saved = await article.save();
    res.status(201).json(saved);
  } catch (err) {
    res.status(500).json({ message: 'Server error creating article' });
  }
});

// Update article
app.put('/api/articles/:id', async (req, res) => {
  const { id } = req.params;
  const { title, content } = req.body;

  if (!isValidObjectId(id))
    return res.status(400).json({ message: 'Invalid article ID' });

  if (!title && !content)
    return res.status(400).json({ message: 'At least one of title or content must be provided' });

  try {
    const article = await Article.findById(id);
    if (!article) return res.status(404).json({ message: 'Article not found' });

    if (title) article.title = title;
    if (content) article.content = content;

    const updated = await article.save();
    res.json(updated);
  } catch (err) {
    res.status(500).json({ message: 'Server error updating article' });
  }
});

// Delete article
app.delete('/api/articles/:id', async (req, res) => {
  const { id } = req.params;

  if (!isValidObjectId(id))
    return res.status(400).json({ message: 'Invalid article ID' });

  try {
    const article = await Article.findById(id);
    if (!article) return res.status(404).json({ message: 'Article not found' });

    await article.deleteOne();
    res.json({ message: 'Article deleted' });
  } catch (err) {
    res.status(500).json({ message: 'Server error deleting article' });
  }
});


// ===================== METAMASK AUTH =====================

// ====== Request Nonce ======

app.post("/auth/request-nonce", async (req, res) => {
  try {
    const { wallet } = req.body;

    if (!wallet) {
      return res.status(400).json({ message: "Wallet address required" });
    }

    const lower = wallet.toLowerCase();

    // Correct lookup for multi-wallet user
    let user = await User.findOne({ wallets: lower });

    // If wallet NOT found → create new user entry
    if (!user) {
      user = new User({
        wallets: [lower], 
        nonce: Math.floor(Math.random() * 1000000).toString()
      });

      await user.save();
    } else {
      // Wallet exists → generate new nonce for login
      user.nonce = Math.floor(Math.random() * 1000000).toString();
      await user.save();
    }

    res.json({ wallet: lower, nonce: user.nonce });

  } catch (err) {
    console.error("🔥 NONCE ERROR:", err);

return res.status(500).json({
  message: "Server error requesting nonce",
  error: err.message,
  stack: err.stack
});




// ====== Verify Signature (Login) ======
app.post("/auth/verify", async (req, res) => {
  try {
    const { wallet, signature } = req.body;

    if (!wallet || !signature)
      return res.status(400).json({ message: "Wallet and signature required" });

    const user = await User.findOne({ wallets: wallet.toLowerCase() });

    if (!user)
      return res.status(404).json({ message: "User not found" });

    // Build message
    const message = `Login nonce: ${user.nonce}`;

    const messageBuffer = Buffer.from(message);
    const msgHash = ethUtil.hashPersonalMessage(messageBuffer);

    const sig = ethUtil.fromRpcSig(signature);
    const publicKey = ethUtil.ecrecover(msgHash, sig.v, sig.r, sig.s);
    const recoveredWallet = ethUtil.bufferToHex(ethUtil.pubToAddress(publicKey));

    if (recoveredWallet.toLowerCase() !== wallet.toLowerCase()) {
      return res.status(401).json({ message: "Signature verification failed" });
    }

    // Success → new nonce
    user.nonce = Math.floor(Math.random() * 1000000).toString();
    await user.save();

    const token = jwt.sign(
      { wallet },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({ message: "Login success", token, wallet });

  } catch (err) {
    console.error("Verify Error:", err);
    res.status(500).json({ message: "Server error verifying signature" });
  }
});


// Start Server
app.listen(PORT, () =>
  console.log(`🚀 Server running on port ${PORT}`)
);
