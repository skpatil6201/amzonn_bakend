const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const crypto = require('crypto');

dotenv.config();

const app = express();
const port = 8085;

// Function to generate a random secret key
const generateSecretKey = (length = 64) => {
  return crypto.randomBytes(length).toString('hex'); // Generates a random hex string of 64 bytes
};

const SECRET_KEY = process.env.SECRET_KEY || generateSecretKey();

app.use(express.json());
app.use(cors());

// MongoDB Connection
const url = process.env.MONGO_URL || "mongodb+srv://tejaspatil77777:BMkjEiROuTg4HPKM@cluster0.vpbjx.mongodb.net/?retryWrites=true&w=majority";
mongoose
  .connect(url, { useNewUrlParser: true, useUnifiedTopology: true, connectTimeoutMS: 30000 })
  .then(() => console.log('Connected to MongoDB Atlas successfully'))
  .catch((err) => console.error('Error connecting to MongoDB Atlas:', err));

// User Schema
const userSchema = new mongoose.Schema({
  username: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});

// Pre-save hook for password hashing
userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  try {
    this.password = await bcrypt.hash(this.password, 10);
    next();
  } catch (err) {
    next(err);
  }
});

// User model
const User = mongoose.model('User', userSchema);

// Register Route
app.post('/register', async (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    return res.status(400).json({ error: "All fields are required!" });
  }

  try {
    const newUser = new User({ username, email, password });
    const savedUser = await newUser.save();
    res.status(201).json({ message: "User registered successfully!", user: { username: savedUser.username, email: savedUser.email } });
  } catch (err) {
    if (err.code === 11000) {
      res.status(409).json({ error: "Email already exists!" });
    } else {
      res.status(500).json({ error: "Internal Server Error", details: err.message });
    }
  }
});

// Login Route
const emailRegex = /^[\w-]+(\.[\w-]+)*@([\w-]+\.)+[a-zA-Z]{2,7}$/;

app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: "Email and password are required!" });
  }

  if (!emailRegex.test(email)) {
    return res.status(400).json({ error: "Invalid email format!" });
  }

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ error: "User not found!" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: "Invalid credentials!" });
    }

    const token = jwt.sign({ id: user._id, email: user.email }, SECRET_KEY, { expiresIn: '1h' });

    res.status(200).json({
      message: "Login successful!",
      token,
      user: { username: user.username, email: user.email },
    });
  } catch (err) {
    console.error("Error logging in:", err.message); 
    res.status(500).json({ error: "Internal Server Error", details: err.message });
  }
});

// Middleware for Authentication
const authenticate = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({ error: "Authorization token required!" });
  }

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(403).json({ error: "Invalid or expired token!" });
  }
};


// Order Schema
const orderSchema = new mongoose.Schema({
    shippingDetails: {
      name: { type: String, required: true },
      address: { type: String, required: true },
      city: { type: String, required: true },
      postalCode: { type: String, required: true },
      country: { type: String, required: true },
      email: { type: String, required: true },
      paymentMethod: { type: String, required: true },
    },
    items: [
      {
        title: { type: String, required: true },
        detail: { type: String, required: true },
        price: { type: Number, required: true },
      },
    ],
    totalPrice: { type: Number, required: true },
    createdAt: { type: Date, default: Date.now },
  });
  
  const Order = mongoose.model('Order', orderSchema);
  
  // Place Order Route
  app.post('/orders', async (req, res) => {
    const { shippingDetails, items, totalPrice } = req.body;
  
    // Check if all required data is provided
    if (!shippingDetails || !items || !totalPrice) {
      return res.status(400).json({ error: "All order fields must be provided" });
    }
  
    try {
      // Create a new order
      const newOrder = new Order({
        shippingDetails,
        items,
        totalPrice,
      });
  
      // Save the order to the database
      const savedOrder = await newOrder.save();
  
      // Send response to the frontend
      res.status(201).json({ message: "Order placed successfully!", order: savedOrder });
    } catch (err) {
      console.error("Error placing order:", err);
      res.status(500).json({ error: "Error saving order to the database", details: err.message });
    }
  });

// Get Order by ID Route
app.get('/orders/:id', authenticate, async (req, res) => {
  const { id } = req.params;

  try {
    const order = await Order.findById(id); // Fetch the order with the specified ID
    if (!order) {
      return res.status(404).json({ error: "Order not found!" });
    }
    res.status(200).json(order);
  } catch (err) {
    console.error("Error fetching order:", err);
    res.status(500).json({ error: "Error retrieving order from the database", details: err.message });
  }
});



app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
