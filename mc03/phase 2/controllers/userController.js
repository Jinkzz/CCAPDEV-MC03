const User = require('../models/user');
const bcrypt = require('bcrypt');
const SALT_ROUNDS = 10;

exports.getLogin = (req, res) => {
    res.render('login');
};


exports.getRegister = (req, res) => {
    res.render('register');
};


exports.registerUser = async (req, res) => {
    try {
        const { name, password } = req.body;

        
        const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

       
        const newUser = new User({ name, password: hashedPassword });
        await newUser.save();

        res.redirect('/login');
    } catch (error) {
        console.error("Registration error:", error);
        res.status(500).send("Registration failed");
    }
};


exports.getHomepage = (req, res) => {
    res.render('index', { user: req.session.user || null });
};


exports.logout = (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error("Logout error:", err);
            return res.status(500).send("Logout failed");
        }
        res.clearCookie('connect.sid', { path: '/' });
        res.redirect('/login');
    });
};


exports.loginUser = async (req, res) => {
    try {
        const { name, password } = req.body;

        const user = await User.findOne({ name });
        if (!user) {
            return res.send('Invalid username or password');
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.send('Invalid username or password');
        }

        req.session.user = user;
        console.log("Session Set:", req.session.user);

        req.session.save(err => {
            if (err) {
                console.error("Session save error:", err);
                return res.status(500).send("Login failed");
            }
            res.redirect('/');
        });
    } catch (error) {
        console.error("Login error:", error);
        res.status(500).send("Login failed");
    }
};






