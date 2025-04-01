const User = require('../models/user');

exports.getLogin = (req, res) => {
    res.render('login');
};

exports.getRegister = (req, res) => {
    res.render('register');
};

exports.registerUser = async (req, res) => {
    const { name, password } = req.body;
    const newUser = new User({ name, password });
    await newUser.save();
    res.redirect('/login');
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
        res.clearCookie('connect.sid', { path: '/' }); // Clear session cookie
        res.redirect('/login'); // Redirect to login page
    });
};

exports.loginUser = async (req, res) => {
    const { username, password } = req.body;
    const user = await User.findOne({ username, password });

    if (!user) {
        return res.send('Invalid username or password');
    }

    req.session.user = user;
    console.log("Session Set:", req.session.user); // Check if session is actually set

    req.session.save(err => {
        if (err) {
            console.error("Session save error:", err);
            return res.status(500).send("Login failed");
        }
        res.redirect('/');
    });
};





