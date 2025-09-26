const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const path = require("path");
const dotenv = require("dotenv");
const db = require("./database");
const fileUpload = require("express-fileupload");

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());
app.use(fileUpload());
app.use("/uploads", express.static(path.join(__dirname, "uploads")));



app.post("/register", async (req, res) => {
  const { username, email, password, role } = req.body;

  // Check if all fields are provided
  if (!username || !email || !password || !role) {
    return res.status(400).json({
      error: "All fields (username, email, password, role) are required",
    });
  }

  // Optional: restrict role values
  const allowedRoles = ["requester", "staff"];
  if (!allowedRoles.includes(role)) {
    return res
      .status(400)
      .json({ error: "Invalid role. Must be 'requester' or 'staff'" });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    const sql =
      "INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)";
    db.query(sql, [username, email, hashedPassword, role], (err, result) => {
      if (err) {
        if (err.code === "ER_DUP_ENTRY") {
          return res
            .status(400)
            .json({ error: "Username or Email already exists" });
        }
        return res.status(500).json({ error: "Database error", details: err });
      }

      res.status(201).json({ message: "User registered successfully" });
    });
  } catch (err) {
    res.status(500).json({ error: "Server error", details: err.message });
  }
});

app.post("/login", (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: "Email and password are required" });
  }

  const sql = "SELECT * FROM users WHERE email = ?";
  db.query(sql, [email], async (err, results) => {
    if (err) return res.status(500).json({ error: "Database error" });

    if (results.length === 0) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    const user = results[0];
    // const isMatch = await bcrypt.compare(password, user.password);
    // if (!isMatch) {
    //   return res.status(401).json({ error: "Invalid password" });
    // }
    if (user.password !== password) {
      return res.status(401).json({ error: "Invalid password" });
    }

    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.json({
      message: "Login successful",
      token,
      id: user.id,
      username: user.username,
      role: user.role,
    });
  });
});

app.put("/user/:id", async (req, res) => {
  const userId = req.params.id;
  const { username, email, password } = req.body;

  if (!username && !email && !password) {
    return res.status(400).json({
      error:
        "At least one field (username, email, or password) must be provided for update",
    });
  }

  // If the user wants to update password, hash the new password safely.
  try {
    let hashedPassword;
    if (password) {
      hashedPassword = await bcrypt.hash(password, 10);
    }

    const fields = [];
    const values = [];

    if (username) {
      fields.push("username = ?");
      values.push(username);
    }
    if (email) {
      fields.push("email = ?");
      values.push(email);
    }
    if (hashedPassword) {
      fields.push("password = ?");
      values.push(hashedPassword);
    }

    values.push(userId);

    const sql = `UPDATE users SET ${fields.join(", ")} WHERE id = ?`;

    db.query(sql, values, (err, result) => {
      if (err) {
        if (err.code === "ER_DUP_ENTRY") {
          return res
            .status(400)
            .json({ error: "Username or Email already exists" });
        }
        return res.status(500).json({ error: "Database error", details: err });
      }

      if (result.affectedRows === 0) {
        return res.status(404).json({ error: "User not found" });
      }

      res.json({ message: "User updated successfully" });
    });
  } catch (err) {
    res.status(500).json({ error: "Server error", details: err.message });
  }
});

app.delete("/user/:id", (req, res) => {
  const userId = req.params.id;

  const sql = "DELETE FROM users WHERE id = ?";
  db.query(sql, [userId], (err, result) => {
    if (err) {
      return res.status(500).json({ error: "Database error", details: err });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json({ message: "User deleted successfully" });
  });
});

app.post("/forgot-password", (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ error: "Email is required" });
  }

  // to generate otp
  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  const otp_expires = new Date(Date.now() + 5 * 60 * 1000);

  // check if the user exist
  const sql = "SELECT * FROM users WHERE email = ?";
  db.query(sql, [email], (err, results) => {
    if (err) return res.status(500).json({ error: "Database error" });

    if (results.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    // Save OTP and expiration in database.
    const updateSql =
      "UPDATE users SET otp = ?, otp_expires = ? WHERE email = ?";
    db.query(updateSql, [otp, otp_expires, email], (err) => {
      if (err) return res.status(500).json({ error: "Failed to save OTP" });

      const transporter = nodemailer.createTransport({
        service: "gmail",
        auth: {
          user: process.env.EMAIL_USER,
          pass: process.env.EMAIL_PASS,
        },
      });

      const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: "Your Password Reset OTP",
        text: `Your OTP is ${otp}. It expires in 5 minutes.`,
      };

      transporter.sendMail(mailOptions, (err, info) => {
        if (err)
          return res
            .status(500)
            .json({ error: "Failed to send OTP", details: err });

        res.json({ message: "OTP sent to email successfully" });
      });
    });
  });
});

app.post("/reset-password", async (req, res) => {
  const { email, otp, newPassword } = req.body;

  if (!email || !otp || !newPassword) {
    return res.status(400).json({ error: "All fields are required" });
  }

  // Verify OTP and email match a user.
  const sql = "SELECT * FROM users WHERE email = ? AND otp = ?";
  db.query(sql, [email, otp], async (err, results) => {
    if (err) return res.status(500).json({ error: "Database error" });

    if (results.length === 0) {
      return res.status(400).json({ error: "Invalid OTP or email" });
    }

    // Check if OTP expired.
    const user = results[0];
    const now = new Date();

    if (new Date(user.otp_expires) < now) {
      return res.status(400).json({ error: "OTP has expired" });
    }

    try {
      const hashedPassword = await bcrypt.hash(newPassword, 10);
      const updateSql =
        "UPDATE users SET password = ?, otp = NULL, otp_expires = NULL WHERE email = ?";
      db.query(updateSql, [hashedPassword, email], (err) => {
        if (err)
          return res.status(500).json({ error: "Failed to reset password" });

        res.json({ message: "Password reset successful" });
      });
    } catch (err) {
      res.status(500).json({ error: "Server error", details: err.message });
    }
  });
});

app.post("/create-delivery", (req, res) => {
  const {
    package_info,
    receiver_address,
    delivery_note,
    sender_name,
    priority,
  } = req.body;

  if (!sender_name || !receiver_address || !package_info) {
    return res
      .status(400)
      .json({ error: "All required fields must be filled" });
  }

  const getDriversSql = "SELECT * FROM drivers WHERE is_available = 1";
  db.query(getDriversSql, (err, drivers) => {
    if (err) {
      return res.status(500).json({ error: "Database error", details: err });
    }

    if (drivers.length === 0) {
      return res.status(400).json({ error: "No available drivers found" });
    }

    const assignedDriver = drivers[Math.floor(Math.random() * drivers.length)];

    const insertSql = `
      INSERT INTO deliveries 
      (sender_name, receiver_address, package_info, delivery_note, status, assigned_driver_id, priority)
      VALUES (?, ?, ?, ?, 'pending', ?, ?)
    `;
    const values = [
      sender_name,
      receiver_address,
      package_info,
      delivery_note || null,
      assignedDriver.id,
      priority || "Medium", // Default to Medium if not provided
    ];

    db.query(insertSql, values, (err, result) => {
      if (err) {
        return res.status(500).json({
          error: "Failed to create delivery",
          details: err,
        });
      }

      const updateDriverSql =
        "UPDATE drivers SET is_available = 0 WHERE id = ?";
      db.query(updateDriverSql, [assignedDriver.id], (err) => {
        if (err) {
          return res.status(500).json({
            error: "Failed to update driver availability",
            details: err,
          });
        }

        res.status(201).json({
          message: `Delivery created and assigned to driver ${assignedDriver.name}`,
          delivery_id: result.insertId,
          driver: assignedDriver,
        });
      });
    });
  });
});

app.get("/assigned-deliveries/:driverId", (req, res) => {
  const driverId = req.params.driverId;

  const sql = `
    SELECT * FROM deliveries
    WHERE assigned_driver_id = ?
  `;

  db.query(sql, [driverId], (err, results) => {
    if (err) {
      return res.status(500).json({ error: "Database error", details: err });
    }

    if (results.length === 0) {
      return res
        .status(404)
        .json({ message: "No deliveries found for this driver" });
    }

    // Send response with deliveries data
    res.status(200).json({
      message: `Deliveries assigned to driver ID ${driverId}`,
      data: results,
    });
  });
});

app.put("/update-delivery-status/:deliveryId", (req, res) => {
  const deliveryId = req.params.deliveryId;
  const { status } = req.body;

  if (!status) {
    return res.status(400).json({ error: "Status is required" });
  }

  const validStatuses = ["pending", "on the way", "delivered"];
  if (!validStatuses.includes(status)) {
    return res.status(400).json({ error: "Invalid status value" });
  }

  const updateSql = "UPDATE deliveries SET status = ? WHERE id = ?";
  db.query(updateSql, [status, deliveryId], (err, result) => {
    if (err) {
      return res.status(500).json({ error: "Database error", details: err });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "Delivery not found" });
    }

    // ✅ Also insert into status history
    const historySql = `
      INSERT INTO delivery_status_updates (delivery_id, status)
      VALUES (?, ?)
    `;
    db.query(historySql, [deliveryId, status], (err) => {
      if (err) {
        return res.status(500).json({
          error: "Failed to log status history",
          details: err,
        });
      }

      res.status(200).json({
        message: `Delivery status updated to "${status}" and timeline recorded`,
        delivery_id: deliveryId,
      });
    });
  });
});

app.post("/upload-proof/:deliveryId", (req, res) => {
  const deliveryId = req.params.deliveryId;

  if (!req.files || !req.files.proof) {
    return res.status(400).json({ error: "No file uploaded" });
  }

  const proofFile = req.files.proof;
  const filename = `proof_${deliveryId}_${Date.now()}_${proofFile.name}`;
  const uploadPath = path.join(__dirname, "uploads", filename);

  // Move file to uploads folder
  proofFile.mv(uploadPath, (err) => {
    if (err) {
      return res
        .status(500)
        .json({ error: "Failed to save file", details: err });
    }

    // Update database
    const sql = "UPDATE deliveries SET proof_of_delivery = ? WHERE id = ?";
    db.query(sql, [filename, deliveryId], (err, result) => {
      if (err) {
        return res
          .status(500)
          .json({ error: "Failed to save proof in DB", details: err });
      }

      res.status(200).json({
        message: "Delivery proof uploaded successfully",
        file_url: `/uploads/${filename}`,
      });
    });
  });
});

app.get("/delivery-history/:senderName", (req, res) => {
  const senderName = req.params.senderName;

  const sql = "SELECT * FROM deliveries WHERE sender_name = ?";
  db.query(sql, [senderName], (err, results) => {
    if (err) {
      return res.status(500).json({ error: "Database error", details: err });
    }

    if (results.length === 0) {
      return res
        .status(404)
        .json({ message: `No deliveries found for sender "${senderName}"` });
    }

    res.status(200).json({
      message: `Delivery history for ${senderName}`,
      data: results,
    });
  });
});

app.get("/delivery-detail/:deliveryId", (req, res) => {
  const deliveryId = parseInt(req.params.deliveryId);

  const sql = "SELECT * FROM deliveries WHERE id = ?";
  db.query(sql, [deliveryId], (err, results) => {
    if (err) {
      return res.status(500).json({ error: "Database error", details: err });
    }

    if (results.length === 0) {
      return res
        .status(404)
        .json({ message: `No deliveries found for sender "${deliveryId}"` });
    }

    res.status(200).json({
      message: `Delivery history for ${deliveryId}`,
      data: results,
    });
  });
});

app.get("/delivery-status-timeline/:deliveryId", (req, res) => {
  const deliveryId = req.params.deliveryId;

  const sql = `
    SELECT status, updated_at
    FROM delivery_status_updates
    WHERE delivery_id = ?
    ORDER BY updated_at ASC
  `;

  db.query(sql, [deliveryId], (err, results) => {
    if (err) {
      return res.status(500).json({ error: "Database error", details: err });
    }

    if (results.length === 0) {
      return res
        .status(404)
        .json({ message: "No timeline found for this delivery" });
    }

    res.status(200).json({
      message: `Timeline for delivery ID ${deliveryId}`,
      timeline: results,
    });
  });
});

app.get("/dashboard-summary", (req, res) => {
  const sql = `
    SELECT 
      COUNT(*) AS total,
      SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) AS pending,
      SUM(CASE WHEN status = 'on the way' THEN 1 ELSE 0 END) AS on the way,
      SUM(CASE WHEN status = 'delivered' THEN 1 ELSE 0 END) AS delivered
    FROM deliveries
  `;

  db.query(sql, (err, results) => {
    if (err) {
      return res.status(500).json({ error: "Database error", details: err });
    }

    const summary = results[0];

    res.status(200).json({
      message: "Dashboard summary fetched successfully",
      summary,
    });
  });
});

app.get("/staff-dashboard/:userId", (req, res) => {
  const userId = req.params.userId;

  // Step 1: Check if user exists and is staff
  const checkUserSql = `SELECT * FROM users WHERE id = ? AND role = 'staff'`;

  db.query(checkUserSql, [userId], (err, userResults) => {
    if (err) {
      return res.status(500).json({ error: "Database error", details: err });
    }

    if (userResults.length === 0) {
      return res.status(403).json({ error: "Access denied. User is not staff." });
    }

    // Step 2: Fetch ALL deliveries (no filter)
    const getAllDeliveriesSql = `SELECT * FROM deliveries`;

    db.query(getAllDeliveriesSql, (err, deliveries) => {
      if (err) {
        return res.status(500).json({ error: "Database error", details: err });
      }

      if (deliveries.length === 0) {
        return res.status(404).json({ message: "No deliveries found." });
      }

      res.status(200).json({
        message: "All deliveries fetched successfully.",
        data: deliveries,
      });
    });
  });
});


const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));