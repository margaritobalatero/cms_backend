const mongoose = require('mongoose');

const atlasUri = 'mongodb+srv://junjie:junjie55@junjiecluster.1cawbvg.mongodb.net/?retryWrites=true&w=majority&appName=mern_cms';

mongoose.connect(atlasUri, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => {
  console.log('Connected to MongoDB Atlas');
  process.exit(0);
})
.catch(err => {
  console.error('Connection error:', err);
  process.exit(1);
});
