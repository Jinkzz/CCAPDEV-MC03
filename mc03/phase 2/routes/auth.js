const express = require('express');
const router = express.Router();
const User = require('../models/user');
const mongoose = require("mongoose");


// ✅ Login Route
router.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await User.findOne({ email }); // Ensure user is defined

        // If user not found or password doesn't match
        if (!user || user.password !== password) {
            return res.status(400).json({ error: 'Invalid email or password' });
        }

        // ✅ Store user details in session
        req.session.user = {
            id: user._id,
            name: user.name,
            email: user.email,
            phone: user.phone
        };

        console.log('User logged in:', req.session.user); // Debugging

        res.redirect('/'); // Redirect to home page after login
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).send('Internal Server Error');
    }
});


// ✅ Logout Route
router.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error("Logout failed:", err);
            return res.status(500).json({ message: 'Logout failed' });
        }
        res.clearCookie('connect.sid', { path: '/' }); // Clear session cookie
        res.redirect('/');
    });
});

router.post("/register", async (req, res) => {
    try {
        const { name, phone, email, password } = req.body;

        // Check if user already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: "User already exists" });
        }

        // Create new user
        const newUser = new User({
            name,
            phone,
            email,
            password,  // Storing password as plain text (⚠ Not recommended for production)
        });

        await newUser.save(); // Save user to MongoDB

        res.status(201).json({ message: "User registered successfully", user: newUser });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Server error" });
    }
});

  
  


module.exports = router;
