// server.js
require("dotenv").config();
const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const { ethers } = require("ethers");
const jwt = require("jsonwebtoken");
const path = require("path");
const mongoose = require("mongoose");
const Item = require("./models/Item"); // your Item model

const app = express();
const PORT = process.env.PORT || 4000;

// --- Environment Variables ---
const MONGO_URI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET || "supersecretjwtkey";

// --- Middleware ---
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public"))); // serve static files

// --- Connect to MongoDB ---
mongoose
  .connect(MONGO_URI)
  .then(() => console.log("MongoDB connected"))
  .catch((err) => console.error("MongoDB connection error:", err));

// --- In-memory nonce map ---
const nonces = new Map();

// =====================
//      AUTH ROUTES
// =====================

// Request nonce for MetaMask login
app.post("/auth/request-nonce", (req, res) => {
  const { wallet } = req.body;
  if (!wallet) return res.status(400).json({ error: "wallet address required" });

  const nonce = `Login nonce: ${Math.floor(Math.random() * 1e9)}`;
  nonces.set(wallet.toLowerCase(), nonce);

  return res.json({ wallet: wallet.toLowerCase(), nonce });
});

// Verify signature and issue JWT
app.post("/auth/verify", async (req, res) => {
  try {
    const { wallet, signature } = req.body;
    if (!wallet || !signature)
      return res.status(400).json({ error: "wallet and signature required" });

    const nonce = nonces.get(wallet.toLowerCase());
    if (!nonce) return res.status(400).json({ error: "nonce not found, request a new one" });

    // Verify signature using ethers.js
    const recovered = ethers.utils.verifyMessage(nonce, signature);
    if (recovered.toLowerCase() !== wallet.toLowerCase()) {
      return res.status(401).json({ error: "signature verification failed" });
    }

    // Signature valid → issue JWT
    const token = jwt.sign({ userId: wallet.toLowerCase() }, JWT_SECRET, { expiresIn: "7d" });

    // Clear nonce after use
    nonces.delete(wallet.toLowerCase());

    return res.json({ token });
  } catch (err) {
    console.error("Error in /auth/verify:", err);
    return res.status(500).json({ error: "server error verifying signature" });
  }
});

// =====================
//    AUTH MIDDLEWARE
// =====================
function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: "missing token" });

  const token = authHeader.split(" ")[1]; // Bearer <token>
  if (!token) return res.status(401).json({ error: "invalid token format" });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded; // contains userId
    next();
  } catch (err) {
    return res.status(401).json({ error: "invalid token" });
  }
}

// =====================
//      CRUD ROUTES
// =====================

// Get all articles for logged-in wallet
app.get("/api/articles", requireAuth, async (req, res) => {
  try {
    const articles = await Item.find({ userId: req.user.userId });
    res.json(articles);
  } catch (err) {
    console.error("Read articles error:", err);
    res.status(500).json({ error: "Failed to fetch articles" });
  }
});

// Get single article
app.get("/api/articles/:id", requireAuth, async (req, res) => {
  try {
    const article = await Item.findOne({ _id: req.params.id, userId: req.user.userId });
    if (!article) return res.status(404).json({ error: "Article not found" });
    res.json(article);
  } catch (err) {
    console.error("Get article error:", err);
    res.status(500).json({ error: "Failed to fetch article" });
  }
});

// Create article
app.post("/api/articles", requireAuth, async (req, res) => {
  try {
    const data = { ...req.body, userId: req.user.userId };
    const newArticle = await Item.create(data);
    res.json(newArticle);
  } catch (err) {
    console.error("Create article error:", err);
    res.status(500).json({ error: "Failed to create article" });
  }
});

// Update article
app.put("/api/articles/:id", requireAuth, async (req, res) => {
  try {
    const article = await Item.findOneAndUpdate(
      { _id: req.params.id, userId: req.user.userId },
      req.body,
      { new: true }
    );
    if (!article) return res.status(404).json({ error: "Article not found" });
    res.json(article);
  } catch (err) {
    console.error("Update article error:", err);
    res.status(500).json({ error: "Failed to update article" });
  }
});

// Delete article
app.delete("/api/articles/:id", requireAuth, async (req, res) => {
  try {
    const deleted = await Item.findOneAndDelete({ _id: req.params.id, userId: req.user.userId });
    if (!deleted) return res.status(404).json({ error: "Article not found" });
    res.json({ ok: true });
  } catch (err) {
    console.error("Delete article error:", err);
    res.status(500).json({ error: "Failed to delete article" });
  }
});

// =====================
//      START SERVER
// =====================
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
