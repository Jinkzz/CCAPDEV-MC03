const express = require('express');
const router = express.Router();
const User = require('../models/user');
const mongoose = require("mongoose");


const userController = require('../controllers/userController');

router.get('/login', userController.getLogin);
router.get('/register', userController.getRegister);
router.post('/register', userController.registerUser);
router.get('/logout', userController.logout);

router.get('/', async (req, res) => {
    console.log("Session Data:", req.session);
    
    if (!req.session || !req.session.user) {
        return res.status(401).json({ message: "User not logged in" });
    }

    try {
        const user = await User.findById(req.session.user._id);
        res.json(user);
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

router.get('/api/user', async (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ success: false, message: "Not logged in" });
    }

    const user = await User.findById(req.session.user.id).select('-password'); // Exclude password

    if (!user) {
        return res.status(404).json({ success: false, message: "User not found" });
    }

    res.json({ success: true, user });
});




module.exports = router;
