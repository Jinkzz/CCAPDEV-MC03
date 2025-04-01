const express = require('express');
const router = express.Router();
const Pet = require('../models/pet');
const petController = require('../controllers/petController'); // Import controller
const mongoose = require("mongoose");


// Route to get available pets
router.get('/pets', petController.getPets);
// Route to fetch all pets
router.get('/', async (req, res) => {
    try {
        const pets = await Pet.find();
        res.render('pets', { pets });
    } catch (err) {
        console.error('Error fetching pets:', err);
        res.status(500).send('Error fetching pets');
    }
});

// ✅ Route to fetch a specific pet by ID
router.get('/:id', async (req, res) => {
    console.log(`📌 Fetching pet with ID: ${req.params.id}`);
    try {
        const pet = await Pet.findById(req.params.id);
        if (!pet) {
            console.log('❌ Pet not found:', req.params.id);
            return res.status(404).send('Pet not found');
        }
        console.log('✅ Found pet:', pet);
        res.render('petDetails', { pet }); // ✅ Render petDetails.ejs
    } catch (err) {
        console.error('❌ Error fetching pet:', err);
        res.status(500).send('Error fetching pet details');
    }
});

router.get("/adopt/:id", (req, res) => {
    const petId = req.params.id;
    
    if (!petId) {
        return res.status(400).send("Pet ID is missing.");
    }

    res.send(`Pet with ID ${petId} has been successfully adopted!`);
});

router.get('/pets', async (req, res) => {
    try {
        const pets = await Pet.find({ adopt: "No" }); // Only fetch pets that are not yet adopted
        res.render('pets', { pets });
    } catch (error) {
        console.error("Error fetching pets:", error);
        res.status(500).send("Internal Server Error");
    }
});

router.post("/adopt/:id", petController.adoptPet);





module.exports = router;
