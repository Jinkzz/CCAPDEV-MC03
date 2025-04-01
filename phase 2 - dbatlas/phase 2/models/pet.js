const mongoose = require('mongoose');

const PetSchema = new mongoose.Schema({
    name: String,
    species: String,
    age: Number,
    description: String,
    image: String,
    adopt: String
});

const Pet = mongoose.model('Pet', PetSchema);
module.exports = Pet;