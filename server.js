const express = require("express");
const bodyParser = require("body-parser");
const mysql = require("mysql2");
const bcrypt = require("bcryptjs");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const path = require("path");
require('dotenv').config(); // Add this to load environment variables

const app = express();
const port = process.env.PORT;

// CORS options
const corsOptions = {
  origin: process.env.CORS_ORIGIN, // Use the CORS origin from the .env file
  methods: ["GET", "POST", "PUT"],  // Allow specific methods
  allowedHeaders: ["Content-Type", "Authorization"]
};

// Middleware
app.use(cors(corsOptions));  // CORS middleware
app.use(bodyParser.json());  // Parse JSON bodies

// Middleware to block access to sensitive files
app.use((req, res, next) => {
  const forbiddenFiles = ['.env', '.git', '.gitignore'];
  if (forbiddenFiles.some(file => req.url.includes(file))) {
      return res.status(403).send('Access denied');
  }
  next();
});

// Serve the static HTML and JS files from the root of 'well-wise-render'
app.use(express.static(__dirname));  // Serve static files from the current directory

// Serve the CSS files from the 'css' folder
app.use('/css', express.static(path.join(__dirname, 'css')));

// MySQL database connection
const db = mysql.createConnection({
  host: process.env.DB_HOST,  // Use the MySQL host from the .env file
  user: process.env.DB_USER,  // Use the MySQL username from the .env file
  password: process.env.DB_PASSWORD,  // Use the MySQL password from the .env file
  database: process.env.DB_NAME,  // Use the MySQL database name from the .env file
});

// Route to serve index.html at the root
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

// Other routes for specific pages
app.get("/calcPage", (req, res) => {
  res.sendFile(path.join(__dirname, "calcPage.html"));
});

app.get("/guide", (req, res) => {
  res.sendFile(path.join(__dirname, "guide.html"));
});

app.get("/main", (req, res) => {
  res.sendFile(path.join(__dirname, "main.html"));
});

app.get("/searchPage", (req, res) => {
  res.sendFile(path.join(__dirname, "searchPage.html"));
});

// Connect to MySQL
db.connect((err) => {
  if (err) {
    console.error("Database connection error:", err);
    return;
  }
  console.log("Connected to the MySQL database (AWS RDS)");
});

// API endpoint for registration
app.post("/register", (req, res) => {
  const { fullname, phone, password } = req.body;

  // Basic field validation
  if (!fullname || !phone || !password) {
    return res
      .status(400)
      .json({ success: false, message: "All fields are required" });
  }

  // Validate phone number format (e.g., 10 digits)
  const phoneRegex = /^[0-9]{10}$/; // Adjust regex as needed
  if (!phoneRegex.test(phone)) {
    return res
      .status(400)
      .json({
        success: false,
        message: "Please enter a valid 10-digit phone number",
      });
  }

  // Validate password length (at least 6 characters)
  if (password.length < 6) {
    return res
      .status(400)
      .json({
        success: false,
        message: "Password must be at least 6 characters long",
      });
  }

  // Hash password
  bcrypt.hash(password, 10, (err, hash) => {
    if (err) {
      console.error("Error hashing password:", err);
      return res
        .status(500)
        .json({ success: false, message: "Error hashing password" });
    }

    // Insert into the database
    const query =
      "INSERT INTO users (fullname, phone, password) VALUES (?, ?, ?)";
    db.query(query, [fullname, phone, hash], (err, result) => {
      if (err) {
        console.error("Error inserting data:", err);
        return res
          .status(500)
          .json({
            success: false,
            message: "The phone number or name is already registered",
          });
      }
      res.json({ success: true, message: "User registered successfully" });
    });
  });
});

// API endpoint for login
app.post("/login", (req, res) => {
  const { phone, password } = req.body;

  const query = "SELECT * FROM users WHERE phone = ?";
  db.query(query, [phone], (err, results) => {
    if (err) {
      console.error("Database query error:", err);
      return res
        .status(500)
        .json({ success: false, message: "Internal server error" });
    }

    if (results.length === 0) {
      return res
        .status(401)
        .json({ success: false, message: "Invalid credentials" });
    }

    const user = results[0];

    bcrypt.compare(password, user.password, (err, isMatch) => {
      if (err) {
        console.error("Error comparing passwords:", err);
        return res
          .status(500)
          .json({ success: false, message: "Login failed" });
      }

      if (!isMatch) {
        return res
          .status(401)
          .json({ success: false, message: "Invalid credentials" });
      }

      const token = jwt.sign(
        { id: user.id, phone: user.phone },
        process.env.JWT_SECRET, // Use the JWT secret from the .env file
        { expiresIn: "1h" }
      );
      res.json({ success: true, token });
    });
  });
});

// Middleware to authenticate token
function authenticateToken(req, res, next) {
  const token = req.headers["authorization"]?.split(" ")[1];

  if (!token) {
    return res.sendStatus(401); // Unauthorized
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {  // Use JWT secret from .env
    if (err) {
      return res.sendStatus(403); // Forbidden
    }
    req.user = user;
    next();
  });
}

// Start the server on specific
app.listen(port, "0.0.0.0", () => {
  console.log(`Server running on https://wellwise.info:${port}`);
});
