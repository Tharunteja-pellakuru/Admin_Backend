// routes/userRoutes.js

const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const pool = require("../db"); // Adjust path as needed

const router = express.Router();

/* ------------------ Authentication Middleware ------------------ */

// Moved from app.js to be used locally in this router.
const authenticateUser = (req, res, next) => {
  try {
    // Typically, tokens are checked in the Authorization header for API calls
    const authHeader = req.headers["authorization"];

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ error: "No token provided" });
    }

    const token = authHeader.split(" ")[1];

    // Make sure process.env.JWT_SECRET is accessible (e.g., via dotenv in app.js)
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    req.user = decoded; // attach user id

    next();
  } catch (err) {
    console.error("Auth Error:", err.message);
    // 403 Forbidden is often more appropriate for failed authentication checks
    return res.status(403).json({ error: "Invalid or expired token" });
  }
};

// All routes below use the middleware.

/* ------------------ CRUD Routes ------------------ */

// GET /admin/users/
router.get("/", authenticateUser, async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT id, full_name AS name, email, role FROM admin_users ORDER BY id DESC`
    );

    return res.status(200).json({
      success: true,
      users: rows,
    });
  } catch (err) {
    console.error("❌ Error fetching users:", err);

    return res.status(500).json({
      success: false,
      error: "Internal server error while fetching users",
    });
  }
});

// POST /admin/users/add-user
router.post("/add-user", authenticateUser, async (req, res) => {
  const { name, email, role } = req.body;

  if (!name || !email || !role) {
    return res.status(400).json({ message: "All fields required" });
  }

  try {
    // 1. Check duplicate email
    const [existing] = await pool.query(
      "SELECT * FROM admin_users WHERE email = ?",
      [email]
    );

    if (existing.length > 0) {
      return res.status(400).json({ message: "User already exists" });
    }

    // 2. Hash default password
    const defaultPassword = "password123";
    const hashedPassword = await bcrypt.hash(defaultPassword, 10);

    // 3. Insert user into DB
    const [result] = await pool.query(
      `INSERT INTO admin_users (full_name, email, password, role)
        VALUES (?, ?, ?, ?)`,
      [name, email, hashedPassword, role]
    );

    const newUser = {
      id: result.insertId,
      name,
      email,
      role,
    };

    return res.json({ user: newUser });
  } catch (err) {
    console.error("Add User Error:", err);
    return res.status(500).json({ message: "Server error" });
  }
});

// DELETE /admin/users/delete-user/:id
router.delete("/delete-user/:id", authenticateUser, async (req, res) => {
  const { id } = req.params;

  try {
    const [result] = await pool.query("DELETE FROM admin_users WHERE id = ?", [
      id,
    ]);

    if (result.affectedRows === 0) {
      return res
        .status(404)
        .json({ success: false, message: "User not found" });
    }

    return res
      .status(200)
      .json({ success: true, message: "User deleted successfully", id });
  } catch (err) {
    console.error("Delete User Error:", err);
    return res
      .status(500)
      .json({ success: false, message: "Server error while deleting user" });
  }
});

// PATCH /admin/users/update-user/:id
router.patch("/update-user/:id", authenticateUser, async (req, res) => {
  const { id } = req.params;
  const { name, email } = req.body;

  if (!name && !email) {
    return res.status(400).json({
      error: "At least one field (name or email) must be provided",
    });
  }

  try {
    let updateFields = [];
    let values = [];

    if (name) {
      updateFields.push("full_name = ?");
      values.push(name);
    }

    if (email) {
      updateFields.push("email = ?");
      values.push(email);
    }

    values.push(id);

    const query = `
      UPDATE admin_users 
      SET ${updateFields.join(", ")}
      WHERE id = ?
    `;

    const [result] = await pool.query(query, values);

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json({ message: "User updated successfully" });
  } catch (err) {
    console.error("Update User Error:", err);

    if (err.code === "ER_DUP_ENTRY") {
      return res.status(409).json({ error: "Email is already in use" });
    }

    res.status(500).json({ error: "Internal server error" });
  }
});

// PATCH /admin/users/update-password/:id
router.patch("/update-password/:id", authenticateUser, async (req, res) => {
  const { id } = req.params;
  const { currentPassword, newPassword } = req.body;

  try {
    if (!currentPassword || !newPassword) {
      return res.status(400).json({ error: "All fields are required" });
    }

    // 1. Fetch user from DB
    const [rows] = await pool.query(
      "SELECT id, password FROM admin_users WHERE id = ?",
      [id]
    );

    if (rows.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    const user = rows[0];

    // 2. Check if current password matches
    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: "Current password is incorrect" });
    }

    // 3. Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // 4. Update password in DB
    await pool.query("UPDATE admin_users SET password = ? WHERE id = ?", [
      hashedPassword,
      id,
    ]);

    return res.json({ message: "Password updated successfully" });
  } catch (err) {
    console.error("Update Password Error:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

module.exports = {
  router: router, // Export the Express router
  authenticateUser: authenticateUser, // Export the function
};
