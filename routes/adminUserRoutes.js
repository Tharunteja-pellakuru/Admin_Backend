// const express = require("express");
// const bcrypt = require("bcrypt");
// const pool = require("../db");
// const authenticateUser = require("../middleware/authenticateUser");

// const router = express.Router();

// /* ---------------- GET ALL USERS ---------------- */
// router.get("/get-all", authenticateUser, async (req, res) => {
//   try {
//     const [rows] = await pool.query(
//       `SELECT id, full_name AS name, email, role FROM admin_users ORDER BY id DESC`
//     );

//     return res.status(200).json({
//       success: true,
//       users: rows,
//     });
//   } catch (err) {
//     return res.status(500).json({ error: "Internal server error" });
//   }
// });

// /* ---------------- ADD USER ---------------- */
// router.post("/add", authenticateUser, async (req, res) => {
//   const { name, email, role } = req.body;

//   if (!name || !email || !role) {
//     return res.status(400).json({ message: "All fields required" });
//   }

//   try {
//     const [existing] = await pool.query(
//       "SELECT * FROM admin_users WHERE email = ?",
//       [email]
//     );

//     if (existing.length > 0) {
//       return res.status(400).json({ message: "User already exists" });
//     }

//     const defaultPassword = "password123";
//     const hashedPassword = await bcrypt.hash(defaultPassword, 10);

//     const [result] = await pool.query(
//       `INSERT INTO admin_users (full_name, email, password, role) VALUES (?, ?, ?, ?)`,
//       [name, email, hashedPassword, role]
//     );

//     return res.json({
//       user: {
//         id: result.insertId,
//         name,
//         email,
//         role,
//       },
//     });
//   } catch (err) {
//     return res.status(500).json({ message: "Server error" });
//   }
// });

// /* ---------------- DELETE USER ---------------- */
// router.delete("/delete/:id", authenticateUser, async (req, res) => {
//   const { id } = req.params;

//   try {
//     const [result] = await pool.query("DELETE FROM admin_users WHERE id = ?", [
//       id,
//     ]);

//     if (result.affectedRows === 0) {
//       return res.status(404).json({ message: "User not found" });
//     }

//     return res.json({ message: "User deleted successfully", id });
//   } catch (err) {
//     return res.status(500).json({ message: "Server error" });
//   }
// });

// /* ---------------- UPDATE USER DETAILS ---------------- */
// router.patch("/update/:id", authenticateUser, async (req, res) => {
//   const { id } = req.params;
//   const { name, email } = req.body;

//   if (!name && !email) {
//     return res
//       .status(400)
//       .json({ error: "At least one field is required to update" });
//   }

//   try {
//     let updateFields = [];
//     let values = [];

//     if (name) {
//       updateFields.push("full_name = ?");
//       values.push(name);
//     }

//     if (email) {
//       updateFields.push("email = ?");
//       values.push(email);
//     }

//     values.push(id);

//     const query = `UPDATE admin_users SET ${updateFields.join(
//       ", "
//     )} WHERE id = ?`;

//     const [result] = await pool.query(query, values);

//     if (result.affectedRows === 0) {
//       return res.status(404).json({ error: "User not found" });
//     }

//     res.json({ message: "User updated successfully" });
//   } catch (err) {
//     res.status(500).json({ error: "Internal server error" });
//   }
// });

// /* ---------------- UPDATE PASSWORD ---------------- */
// router.patch("/password/:id", authenticateUser, async (req, res) => {
//   const { id } = req.params;
//   const { currentPassword, newPassword } = req.body;

//   if (!currentPassword || !newPassword) {
//     return res.status(400).json({ error: "All fields required" });
//   }

//   try {
//     const [rows] = await pool.query(
//       "SELECT id, password FROM admin_users WHERE id = ?",
//       [id]
//     );

//     if (rows.length === 0) {
//       return res.status(404).json({ error: "User not found" });
//     }

//     const user = rows[0];

//     const isMatch = await bcrypt.compare(currentPassword, user.password);
//     if (!isMatch) {
//       return res.status(401).json({ error: "Current password incorrect" });
//     }

//     const hashedPassword = await bcrypt.hash(newPassword, 10);

//     await pool.query("UPDATE admin_users SET password = ? WHERE id = ?", [
//       hashedPassword,
//       id,
//     ]);

//     res.json({ message: "Password updated successfully" });
//   } catch (err) {
//     res.status(500).json({ error: "Internal server error" });
//   }
// });

// module.exports = router;
