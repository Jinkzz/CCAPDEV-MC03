const express = require("express");
const router = express.Router();
const mongoose = require("mongoose");
const Pet = require("../models/pet"); // Ensure correct path

// Adoption route
router.get("/adopt/:id", (req, res) => {
    const petId = req.params.id;
    
    if (!petId) {
        return res.status(400).send("Pet ID is missing.");
    }

    res.send(`Pet with ID ${petId} has been successfully adopted!`);
});

router.post("/adopt/:id", async (req, res) => {
    try {
        const petId = req.params.id;

        // Validate ID format
        if (!mongoose.Types.ObjectId.isValid(petId)) {
            return res.status(400).json({ error: "Invalid pet ID format." });
        }

        // Find the pet and check if it's already adopted
        const pet = await Pet.findById(petId);
        if (!pet) {
            return res.status(404).json({ error: "Pet not found." });
        }

        // Only update if it's currently "no"
        if (pet.adopt === "no") {
            pet.adopt = "yes";
            await pet.save();
            return res.send("<script>alert('Adopted successfully!'); window.location.href = '/';</script>");
        }

        res.json({ success: false, message: "Pet is already adopted." });
    } catch (error) {
        console.error("Error:", error);
        res.status(500).json({ error: "Server error." });
    }
});




module.exports = router;
