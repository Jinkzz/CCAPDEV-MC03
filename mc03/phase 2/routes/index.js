const express = require('express');
const router = express.Router();
const mongoose = require("mongoose");



// Controllers (assuming you have controllers for these)
const petController = require('../controllers/petController');
const userController = require('../controllers/userController');


// Route for Home Page
router.get('/', (req, res) => {
    res.render('index', { user: req.session.user || null }); // Pass user or null if not logged in
});

router.get('/logout', userController.logout);


router.get('/', (req, res) => {
    console.log("GET / route accessed!");
    res.render('index');
});

router.get('/about', (req, res) => {
    res.render('about'); // This will render views/about.ejs
});

// Route for Login Page
router.get('/login', (req, res) => {
    res.render('login');
});

// Route for Register Page
router.get('/register', (req, res) => {
    res.render('register');
});

// Route for Pets Page
router.get('/pets', petController.getPets);

module.exports = router;
