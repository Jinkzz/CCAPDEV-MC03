const User = require('./models/user');
const Pet = require('./models/pet');
const session = require('express-session');
const cors = require("cors");
const express = require('express');
const mongoose = require('mongoose');
const path = require('path');
const app = express();
const petsRoutes = require('./routes/pet');
const { MongoClient, ObjectId } = require("mongodb"); // <-- Add this if missing


app.use(express.json());
app.use(cors());


// Replace with your actual MongoDB connection string
const mongoURI = "mongodb+srv://ccapdev:ccapdev123@phase2.tnb1k.mongodb.net/phase2";
const dbName = "phase2"; // Use your actual database name

let db;

MongoClient.connect(mongoURI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(client => {
        db = client.db(dbName);
        console.log("Connected to MongoDB");
    })
    .catch(error => console.error("MongoDB connection error:", error));

// Connect to MongoDB
mongoose.connect('mongodb+srv://ccapdev:ccapdev123@phase2.tnb1k.mongodb.net/phase2', {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => console.log('MongoDB Connected'))
.catch(err => console.error("MongoDB connection error:", err));

// Session Configuration
app.use(session({
    secret: 'your_secret_key', 
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: false,  // Change this
      secure: false, 
      maxAge: 24 * 60 * 60 * 1000  // 1 day session
  }
}));

// 🔹 Middleware: Make `user` available in all EJS files
app.use((req, res, next) => {
    res.locals.user = req.session.user || null;
    next();
});

// Set View Engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));  // Ensure correct path

// Middleware for Parsing
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Static Files
app.use(express.static(path.join(__dirname, 'public')));

app.use((req, res, next) => {
  console.log("Session User:", req.session.user); // Debugging session
  next();
});

const adoptionRoutes = require("./routes/adoption"); // Import routes
app.use("/petdetails", adoptionRoutes); // Use adoption routes



// Import & Use Routes
const indexRoutes = require('./routes/index');
const authRoutes = require('./routes/auth');
const userRoutes = require('./routes/user');
app.use("/api/auth", require("./routes/auth")); // Register auth routes


app.use('/', indexRoutes);
app.use('/auth', authRoutes);
app.use('/pets', petsRoutes);
app.use('/api/user', userRoutes); // Mount the route

// Logout Route
app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error("Logout failed:", err);
            return res.status(500).json({ message: 'Logout failed' });
        }
        res.clearCookie('connect.sid', { path: '/' }); // Clear session cookie
        res.redirect('/');
    });
});


// Registration Route
app.post("/api/auth/register", async (req, res) => {
    try {
      const { name, phone, email, password } = req.body;
      
      // Check if user exists
      const existingUser = await User.findOne({ email });
      if (existingUser) return res.status(400).json({ message: "Email already registered" });
  
      const newUser = new User({ name, phone, email, password });
      await newUser.save();
  
      res.json({ message: "User registered successfully!" });
    } catch (error) {
      console.error("Error:", error);
      res.status(500).json({ message: "Server error" });
    }
  });

  app.get("/check-auth", (req, res) => {
    if (!req.user) {
        return res.status(401).json({ isAuthenticated: false });
    }
    res.json({ isAuthenticated: true, user: req.user });
});

app.post("/login", (req, res) => {
  req.session.user = req.body.email; // Store user in session
  res.json({ success: true, user: req.body.email });
});

app.get('/', (req, res) => {
  console.log("Homepage Session:", req.session.user);
  res.render('index', { user: req.session.user || null });
});

app.get('/user', (req, res) => {
  if (req.session.user) {
      res.json({ user: req.session.user });
  } else {
      res.json({ user: null });
  }
});


app.post("/adopt/:id", async (req, res) => {
  try {
      const petId = req.params.id;
      console.log("Received adoption request for Pet ID:", petId); // Debugging

      if (!ObjectId.isValid(petId)) {
          console.error("Invalid Pet ID format.");
          return res.status(400).json({ error: "Invalid pet ID" });
      }

      const result = await Pet.findByIdAndUpdate(
          petId,
          { adopt: "yes" },
          { new: true }
      );

      if (result) {
          console.log("Adoption successful. Updated Pet:", result); // Log the updated pet
          return res.json({ success: true, message: "Adopted12 successfully!", pet: result });
      } else {
          console.error("Pet not found in database.");
          return res.status(404).json({ error: "Pet not found" });
      }
  } catch (error) {
      console.error("Error updating adoption status:", error);
      return res.status(500).json({ error: "Server error" });
  }
});




  

// Start Server
const PORT = 3000;
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
