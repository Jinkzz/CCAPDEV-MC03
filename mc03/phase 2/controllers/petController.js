const Pet = require('../models/pet');

exports.getPets = async (req, res) => {
    try {
        const pets = await Pet.find({ adopt: "no" }); // Fetch only pets that are not adopted

        // Separate pets into dogs and cats
        const dogs = pets.filter(pet => pet.species.toLowerCase() === 'dog');
        const cats = pets.filter(pet => pet.species.toLowerCase() === 'cat');

        res.render('pets', { dogs, cats }); // Pass both categories to EJS
    } catch (error) {
        console.error("Error fetching pets:", error);
        res.status(500).send('Error fetching pets');
    }
};

exports.adoptPet = async (req, res) => {
    try {
        const petId = req.params.id;
        console.log("Pet ID received:", petId); // Debugging line

        const updatedPet = await Pet.findByIdAndUpdate(petId, { adopt: "yes" }, { new: true });

        if (!updatedPet) {
            return res.status(404).json({ success: false, message: "Pet not found" });
        }

        return res.json({ success: true, message: "Adopted successfully!" });
    } catch (error) {
        console.error("Error updating adoption status:", error); // Log the error
        res.status(500).json({ success: false, message: "Error updating adoption status" });
    }
};





