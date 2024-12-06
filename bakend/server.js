const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const port = 8085;

// Secret key for JWT (use environment variables in production)
const SECRET_KEY = 'your_secret_key';

// Middleware
app.use(express.json());
app.use(cors());

//create token
const createtoken =async()=>{
    const newtoken = await jwt.sign({id:"4dsd4d4dd55441d4s5d4s"},"imtejasharnefromamravati")
    process.env.SECRET_KEY=newtoken; 
}
createtoken()
mongoose.set('strictQuery', true); // Or false, depending on your preference

// MongoDB Connection URL
const url = "mongodb+srv://tejaspatil77777:BMkjEiROuTg4HPKM@cluster0.vpbjx.mongodb.net/?retryWrites=true&w=majority";
mongoose.connect(url, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    connectTimeoutMS: 30000, // 30 seconds
})
    .then(() => console.log('Connected to MongoDB Atlas successfully'))
    .catch((err) => console.error('Error connecting to MongoDB Atlas:', err));

// Define a Schema for User Data
const userSchema = new mongoose.Schema({
    username: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
});

// Hash the password before saving the user
userSchema.pre('save', async function (next) {
    if (!this.isModified('password')) return next();
    try {
        this.password = await bcrypt.hash(this.password, 10);
        next();
    } catch (err) {
        next(err);
    }
});

// Create a Model
const User = mongoose.model('User', userSchema);

// Routes
// Home Route
app.get('/', (req, res) => res.status(200).json({ message: "Hello, home page!" }));

// POST Route to Register a User
app.post('/register', async (req, res) => {
    const { username, email,  password } = req.body;

    // Validate Request Body
    if (!username || !email || !password) {
        return res.status(400).json({ error: "All fields are required!" });
    }

    try {
        // Create and Save New User
        const newUser = new User({ username, email, password });
        const savedUser = await newUser.save();
        res.status(201).json({ message: "User registered successfully!", user: savedUser });
    } catch (err) {
        if (err.code === 11000) {
            res.status(409).json({ error: "Email already exists!" });
        } else {
            res.status(500).json({ error: "Internal Server Error", details: err.message });
        }
    }
});

// POST Route to Login and Generate JWT
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    // Validate Request Body
    if (!email || !password) {
        return res.status(400).json({ error: "Email and password are required!" });
    }

    try {
        // Find User by Email
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ error: "User not found!" });
        }

        // Check Password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ error: "Invalid credentials!" });
        }

        // Generate JWT
        const token = jwt.sign({ id: user._id, email: user.email }, SECRET_KEY, { expiresIn: '1h' });
        res.status(200).json({ message: "Login successful!", token });
    } catch (err) {
        res.status(500).json({ error: "Internal Server Error", details: err.message });
    }
});

// Middleware to Protect Routes
const authenticate = (req, res, next) => {
    const authHeader = req.headers.authorization;

    if (!authHeader) {
        return res.status(401).json({ error: "Authorization token required!" });
    }

    const token = authHeader.split(' ')[1]; // Extract token from "Bearer <token>"
    try {
        const decoded = jwt.verify(token, SECRET_KEY);
        req.user = decoded; // Attach decoded token data to request object
        next();
    } catch (err) {
        res.status(403).json({ error: "Invalid or expired token!" });
    }
};

// Protected Route Example
app.get('/protected', authenticate, (req, res) => {
    res.status(200).json({ message: "You have accessed a protected route!", user: req.user });
});

// Start the Server
app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
});
