const mysql = require("mysql2");
require("dotenv").config();

const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

db.connect((err) => {
  if (err) {
    console.error("❌ DB connection failed:", err.message);
    process.exit(1);
  }
  console.log("✅ MySQL connected to database:", process.env.DB_NAME);
});

module.exports = db;
