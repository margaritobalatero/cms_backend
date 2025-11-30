const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

// Connect to MongoDB
mongoose.connect('mongodb+srv://junjie:junjie55@junjiecluster.1cawbvg.mongodb.net/mern_cms?retryWrites=true&w=majority&appName=mern_cms', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('MongoDB connected'))
.catch(err => {
  console.error('MongoDB connection error:', err);
  process.exit(1); // Exit if DB connection fails
});

// Article Schema and Model
const articleSchema = new mongoose.Schema({
  title: { type: String, required: true },
  content: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
});

const Article = mongoose.model('Article', articleSchema);

// Helper: Validate ObjectId
const isValidObjectId = (id) => mongoose.Types.ObjectId.isValid(id);

// Routes

// Get all articles
app.get('/api/articles', async (req, res) => {
  try {
    const articles = await Article.find().sort({ createdAt: -1 });
    res.json(articles);
  } catch (err) {
    console.error('Error fetching articles:', err);
    res.status(500).json({ message: 'Server error fetching articles' });
  }
});

// GET /api/articles/search?q=keyword
app.get('/api/articles/search', async (req, res) => {
  try {
    const query = req.query.q || "";

    const results = await Article.find({
      $or: [
        { title: { $regex: query, $options: "i" } },
        { content: { $regex: query, $options: "i" } }
      ]
    });

    res.json(results);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get single article by ID
app.get('/api/articles/:id', async (req, res) => {
  const { id } = req.params;
  if (!isValidObjectId(id)) {
    return res.status(400).json({ message: 'Invalid article ID' });
  }

  try {
    const article = await Article.findById(id);
    if (!article) return res.status(404).json({ message: 'Article not found' });
    res.json(article);
  } catch (err) {
    console.error('Error fetching article:', err);
    res.status(500).json({ message: 'Server error fetching article' });
  }
});

// Create new article
app.post('/api/articles', async (req, res) => {
  const { title, content } = req.body;
  if (!title || !content) {
    return res.status(400).json({ message: 'Title and content are required' });
  }

  try {
    const article = new Article({ title, content });
    const savedArticle = await article.save();
    res.status(201).json(savedArticle);
  } catch (err) {
    console.error('Error creating article:', err);
    res.status(500).json({ message: 'Server error creating article' });
  }
});

// Update article by ID
app.put('/api/articles/:id', async (req, res) => {
  const { id } = req.params;
  const { title, content } = req.body;

  if (!isValidObjectId(id)) {
    return res.status(400).json({ message: 'Invalid article ID' });
  }
  if (!title && !content) {
    return res.status(400).json({ message: 'At least one of title or content must be provided' });
  }

  try {
    const article = await Article.findById(id);
    if (!article) return res.status(404).json({ message: 'Article not found' });

    if (title) article.title = title;
    if (content) article.content = content;

    const updatedArticle = await article.save();
    res.json(updatedArticle);
  } catch (err) {
    console.error('Error updating article:', err);
    res.status(500).json({ message: 'Server error updating article' });
  }
});

// Delete article by ID
app.delete('/api/articles/:id', async (req, res) => {
  const { id } = req.params;
  console.log('Delete request for article ID:', id);

  if (!mongoose.Types.ObjectId.isValid(id)) {
    console.log('Invalid ObjectId:', id);
    return res.status(400).json({ message: 'Invalid article ID' });
  }

  try {
    const article = await Article.findById(id);
    if (!article) {
      console.log('Article not found:', id);
      return res.status(404).json({ message: 'Article not found' });
    }

    await article.deleteOne();
    console.log('Article deleted:', id);
    res.json({ message: 'Article deleted' });
  } catch (err) {
    console.error('Error deleting article:', err.stack || err);
    res.status(500).json({ message: 'Server error deleting article' });
  }
});

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
