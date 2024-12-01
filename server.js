const express = require("express");
const bodyParser = require("body-parser");
const mysql = require("mysql2");
const bcrypt = require("bcryptjs");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const path = require("path");

const app = express();
const port = process.env.PORT || 2000;

// CORS options
const corsOptions = {
  origin: "https://wellwise.info", // Allow only requests from this origin
  methods: ["GET", "POST", "PUT", "DELETE"],  // Allow specific methods
  allowedHeaders: "*",  // Allow any headers in requests
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
  host: "fooddata.czio48s4mhh9.ap-southeast-1.rds.amazonaws.com", // Use your MySQL host
  user: "welltbn",  // Use your MySQL username
  password: "fofo1234",  // Use your MySQL password
  database: "fooddata",  // Your database name
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
        "your_jwt_secret",
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

  jwt.verify(token, "your_jwt_secret", (err, user) => {
    if (err) {
      return res.sendStatus(403); // Forbidden
    }
    req.user = user;
    next();
  });
}

// Protected route to serve calcPage
app.get("/calcPage", authenticateToken, (req, res) => {
  res.sendFile(path.join(__dirname, "calcPage.html")); // Serve calcPage.html directly
});

// Protected route to serve calcPage
app.get("/guide", authenticateToken, (req, res) => {
  res.sendFile(path.join(__dirname, "guide.html")); // Serve calcPage.html directly
});

// Protected route to serve calcPage
app.get("/main", authenticateToken, (req, res) => {
  res.sendFile(path.join(__dirname, "main.html")); // Serve main.html directly
});

// Protected route to serve index
app.get("/searchPage", authenticateToken, (req, res) => {
  res.sendFile(path.join(__dirname, "searchPage.html")); // Serve index.html directly
});



// Route to fetch data from the meals table with pagination and filtering
app.get("/data", (req, res) => {
  const { page = 1, limit = 15, calories, protein, carbohydrates } = req.query;
  let query = "SELECT COUNT(*) AS totalRecords FROM meals WHERE 1=1";

  if (calories) {
    query += ` AND calories = ${mysql.escape(calories)}`;
  }

  if (protein) {
    query += ` AND protein = ${mysql.escape(protein)}`;
  }

  if (carbohydrates) {
    query += ` AND carbohydrates = ${mysql.escape(carbohydrates)}`;
  }

  db.query(query, (error, countResults) => {
    if (error) {
      console.error("Error executing count query:", error);
      return res.status(500).send("Error counting total records");
    }

    const totalRecords = countResults[0].totalRecords;
    const totalPages = Math.ceil(totalRecords / limit);
    const offset = (page - 1) * limit;

    let dataQuery = "SELECT * FROM meals WHERE 1=1";

    if (calories) {
      const parsedCalories = parseInt(calories, 10); // Parse as integer
      dataQuery += ` AND calories BETWEEN ${mysql.escape(
        Math.max(0, parsedCalories - 100)
      )} AND ${mysql.escape(parsedCalories + 100)}`;
    }
    if (protein) {
      const parsedProtein = parseInt(protein, 10); // Parse as integer
      dataQuery += ` AND protein BETWEEN ${mysql.escape(
        Math.max(0, parsedProtein - 5)
      )} AND ${mysql.escape(parsedProtein + 15)}`;
    }
    if (carbohydrates) {
      const parsedCarbohydrates = parseInt(carbohydrates, 10); // Parse as integer
      dataQuery += ` AND carbohydrates BETWEEN ${mysql.escape(
        Math.max(0, parsedCarbohydrates - 10)
      )} AND ${mysql.escape(parsedCarbohydrates + 10)}`;
    }

    dataQuery += ` LIMIT ${mysql.escape(limit)} OFFSET ${mysql.escape(offset)}`;

    db.query(dataQuery, (error, results) => {
      if (error) {
        console.error("Error executing data query:", error);
        return res.status(500).send("Error fetching data from database");
      }

      const responseData = {
        data: results,
        totalPages: totalPages,
      };

      res.json(responseData);
    });
  });
});

// Start the server on specific
app.listen(port, "0.0.0.0", () => {
  console.log(`Server running on https://wellwise.info:${port}`);
});
