require('dotenv').config(); // Import dotenv at the top if you're using a .env file for your environment variables
const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('./models/User'); // Make sure you have this User model created in your project

const app = express();
const morgan = require('morgan');
app.use(bodyParser.json());
app.use(morgan('dev'));

// Replace 'your_mongodb_connection_string' with your actual connection string
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// Middleware to authenticate token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

  if (!token) return res.status(401).send('Access Denied');

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).send('Invalid Token');
    req.user = user;
    next();
  });
};

// Signup endpoint
app.post('/signup', async (req, res) => {
  try {
    const { firstName, lastName, email, password, verifyPassword, dob, gender } = req.body;

    // Check if password and verifyPassword match
    if (password !== verifyPassword) {
      return res.status(400).send('Passwords do not match');
    }

    // Check if the email is already in use
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).send('Email already in use');
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create a new user
    const user = new User({
      firstName,
      lastName,
      email,
      password: hashedPassword,
      dob: new Date(dob), // Ensure this is a Date object
      gender
    });

    await user.save();

    // Respond with success message
    res.status(201).send('User created successfully');
  } catch (error) {
    res.status(500).send(error.message);
  }
});


// Login endpoint
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user || !await bcrypt.compare(password, user.password)) {
      return res.status(401).send('Authentication failed');
    }
    // Generate a JWT token
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ message: 'Login successful', token });
  } catch (error) {
    res.status(500).send(error.message);
  }
});

// Example of a protected route
app.get('/protected', authenticateToken, (req, res) => {
  res.send('Protected information');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
