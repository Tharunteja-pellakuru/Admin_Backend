const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const pool = require("./db");
const cookieParser = require("cookie-parser");
const app = express();
const { v4: uuidv4 } = require("uuid");

/* ------------------ MIDDLEWARE ------------------ */
app.use(express.json());
app.use(cookieParser());
app.use(
  cors({
    origin: "http://localhost:3001",
    credentials: true,
  })
);

/* ------------------ CREATE TABLE FIRST ------------------ */

const createAdminTable = async () => {
  try {
    await pool.query(`
          CREATE TABLE IF NOT EXISTS admin_users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            full_name VARCHAR(100) NOT NULL,
            email VARCHAR(150) NOT NULL UNIQUE,
            password VARCHAR(255) NOT NULL,
            role VARCHAR(20) NOT NULL DEFAULT 'admin',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
          );
        `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS jobs (
        id CHAR(36) PRIMARY KEY,       -- UUID v4
        title TEXT NOT NULL,
        slug TEXT,

        job_details_json TEXT,          -- JSON as TEXT
        description_json TEXT,          -- JSON as TEXT
        basic_form_json TEXT,
        application_form_json TEXT,     -- JSON as TEXT

        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      );
    `);

    console.log("✔ admin_users table ready");
    console.log("✔ jobs table ready");
  } catch (err) {
    console.error("❌ Table creation error:", err);
    process.exit(1);
  }
};

/* ------------------ User Athentication ------------------ */

const authenticateUser = (req, res, next) => {
  try {
    const authHeader = req.headers["authorization"];

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ error: "No token provided" });
    }

    const token = authHeader.split(" ")[1];

    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    req.user = decoded; // attach user id

    next();
  } catch (err) {
    console.error("Auth Error:", err.message);
    return res.status(401).json({ error: "Invalid or expired token" });
  }
};

/* ------------------ ROUTES ------------------ */

app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const [rows] = await pool.query(
      "SELECT id, full_name AS name, email, password, role FROM admin_users WHERE email = ?",
      [email]
    );

    if (rows.length === 0) {
      return res.status(400).json({ error: "Admin not found" });
    }

    const admin = rows[0];

    const match = await bcrypt.compare(password, admin.password);
    if (!match) {
      return res.status(400).json({ error: "Invalid password" });
    }

    const token = jwt.sign({ id: admin.id }, process.env.JWT_SECRET, {
      expiresIn: "7d",
    });

    // RETURN FULL ADMIN DATA 🔥
    res.json({
      message: "Login successful",
      token,
      user: {
        id: admin.id,
        name: admin.name,
        email: admin.email,
        role: admin.role,
      },
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/signup", async (req, res) => {
  const { full_name, email, password } = req.body;

  try {
    // Password validation
    const passwordRegex =
      /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*])[A-Za-z\d!@#$%^&*]{8,}$/;

    if (!passwordRegex.test(password)) {
      return res.status(400).json({
        error:
          "Password must be at least 8 characters long and include uppercase, lowercase, number, and special character.",
      });
    }

    // Check existing admin
    const [existing] = await pool.query(
      "SELECT * FROM admin_users WHERE email = ?",
      [email]
    );

    if (existing.length > 0) {
      return res.status(400).json({ error: "Admin already exists" });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert
    await pool.query(
      "INSERT INTO admin_users (full_name, email, password) VALUES (?, ?, ?)",
      [full_name, email, hashedPassword]
    );

    res.json({ message: "Admin registered successfully" });
  } catch (err) {
    console.error("Register Error:", err);
    res.status(500).json({ error: err.message });
  }
});

app.get("/", authenticateUser, async (req, res) => {
  try {
    // Fetch all admin users
    const [rows] = await pool.query(
      `SELECT id, full_name AS name, email, role FROM admin_users ORDER BY id DESC`
    );

    // Respond with users (empty array is fine)
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

/* ------------------ Add/Delete Editor ------------------ */
app.post("/add-user", authenticateUser, async (req, res) => {
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

    // 4. Return correct response to frontend
    return res.json({ user: newUser });
  } catch (err) {
    console.error("Add User Error:", err);
    return res.status(500).json({ message: "Server error" });
  }
});

app.delete("/delete-user/:id", authenticateUser, async (req, res) => {
  const { id } = req.params;

  try {
    const [result] = await pool.query("DELETE FROM admin_users WHERE id = ?", [
      id,
    ]);

    // MySQL returns affectedRows in the result object
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

/* ------------------ Save Changes ------------------ */

app.patch("/update-user/:id", authenticateUser, async (req, res) => {
  const { id } = req.params;
  const { name, email } = req.body;

  // Validate input
  if (!name && !email) {
    return res.status(400).json({
      error: "At least one field (name or email) must be provided",
    });
  }

  try {
    // Build dynamic query
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

/* ------------------ Update Password ------------------ */

app.patch("/update-password/:id", authenticateUser, async (req, res) => {
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

/* ------------------ Jobs Posts ------------------ */

app.post("/add-jobs", authenticateUser, async (req, res) => {
  try {
    const jobId = uuidv4();

    const {
      title,
      slug,
      jobDetails,
      jobDescription,
      basicFormSchema,
      applicationForm,
    } = req.body;

    // --- EXECUTE INSERT QUERY ---
    // Note: We use data here, but MySQL/MariaDB returns metadata (insertId/affectedRows),
    // not the inserted row content, so we must construct the job object manually.
    await pool.query(
      `INSERT INTO jobs 
         (id, title, slug, job_details_json, description_json, basic_form_json, application_form_json, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, NOW())`, // Added NOW() for created_at
      [
        jobId,
        title,
        slug || null,
        JSON.stringify(jobDetails || {}),
        JSON.stringify(jobDescription || {}),
        JSON.stringify(basicFormSchema || []),
        JSON.stringify(applicationForm || {}),
      ]
    );

    // --- 1. Construct the complete posted job object ---
    // Use the data received from the client and the generated ID.
    const postedJob = {
      id: jobId,
      title: title,
      slug: slug || null,
      jobDetails: jobDetails || {},
      jobDescription: jobDescription || {},
      basicFormSchema: basicFormSchema || [],
      applicationForm: applicationForm || {},
      createdAt: new Date().toISOString(), // Use current timestamp for return data consistency
    };

    // --- 2. Return the posted job data ---
    return res.status(201).json({
      message: "Job Post Created successfully",
      job: postedJob, // Return the full object under the 'job' key
    });
  } catch (error) {
    console.error("Error in posting a job:", error);
    // Use the 'error' object name consistently for logging
    return res.status(500).json({ error: "Internal server error" });
  }
});

/* ------------------ Jobs Posts (DELETE) ------------------ */

app.delete("/jobs/:id", authenticateUser, async (req, res) => {
  const { id } = req.params;

  try {
    // 1. Execute deletion
    const [result] = await pool.query("DELETE FROM jobs WHERE id = ?", [id]);

    // 2. Check if the job was found and deleted
    if (result.affectedRows === 0) {
      return res.status(404).json({
        success: false,
        message: "Job not found or already deleted.",
      });
    }

    // 3. Return success confirmation
    return res.status(200).json({
      success: true,
      message: "Job deleted successfully",
      id: id,
    });
  } catch (error) {
    console.error("Error deleting job:", error);
    return res.status(500).json({
      success: false,
      message: "Internal server error during job deletion.",
    });
  }
});

/* ------------------ Jobs Posts (UPDATE/PATCH) ------------------ */

app.patch("/jobs/:id", authenticateUser, async (req, res) => {
  const { id } = req.params;
  const {
    title,
    slug,
    job_details_json,
    description_json,
    basic_form_json,
    application_form_json,
  } = req.body;

  try {
    // 1. Fetch current job data to handle partial updates
    const [currentJobRows] = await pool.query(
      "SELECT * FROM jobs WHERE id = ?",
      [id]
    );

    if (currentJobRows.length === 0) {
      return res.status(404).json({ success: false, message: "Job not found" });
    }

    const currentJob = currentJobRows[0];

    // 2. Build dynamic fields for UPDATE query
    let updateFields = [];
    let values = [];

    // Update top-level fields
    if (title !== undefined) {
      updateFields.push("title = ?");
      values.push(title);
    }
    if (slug !== undefined) {
      updateFields.push("slug = ?");
      values.push(slug);
    }

    // Update JSON fields (deserialize current, merge incoming, then reserialize)

    // This is simplified, assuming the client (StoreContext) sends the ENTIRE updated JSON string.
    // If client sends JSON objects, you must merge them here.

    if (job_details_json !== undefined) {
      updateFields.push("job_details_json = ?");
      values.push(job_details_json);
    }
    if (description_json !== undefined) {
      updateFields.push("description_json = ?");
      values.push(description_json);
    }
    if (basic_form_json !== undefined) {
      updateFields.push("basic_form_json = ?");
      values.push(basic_form_json);
    }
    if (application_form_json !== undefined) {
      updateFields.push("application_form_json = ?");
      values.push(application_form_json);
    }

    if (values.length === 0) {
      return res
        .status(400)
        .json({ success: false, message: "No fields provided for update" });
    }

    // 3. Execute the Update
    values.push(id); // ID goes last for the WHERE clause
    const query = `UPDATE jobs SET ${updateFields.join(", ")} WHERE id = ?`;

    await pool.query(query, values);

    // 4. Construct and return the UPDATED job object (deserializing JSON columns)
    const updatedJob = {
      id: currentJob.id,
      title: title || currentJob.title,
      slug: slug || currentJob.slug,

      // Deserialize and return the JSON fields using the updated values
      jobDetails: JSON.parse(job_details_json || currentJob.job_details_json),
      jobDescription: JSON.parse(
        description_json || currentJob.description_json
      ),
      basicFormSchema: JSON.parse(
        basic_form_json || currentJob.basic_form_json
      ),
      applicationForm: JSON.parse(
        application_form_json || currentJob.application_form_json
      ),
    };

    return res.status(200).json({
      success: true,
      message: "Job updated successfully",
      job: updatedJob,
    });
  } catch (error) {
    console.error("Error updating job:", error);
    return res
      .status(500)
      .json({ success: false, error: "Internal server error" });
  }
});

/* ------------------ Jobs List  ------------------ */
app.get("/jobs", async (req, res) => {
  try {
    // 1. Fetch data from the database
    // NOTE: Column names must match your SQL schema (e.g., job_details_json)
    const result = await db.query(
      "SELECT id, title, slug, job_details_json, description_json, basic_form_json, application_form_json FROM jobs"
    );

    console.log(result);
    // 2. Map and Deserialize JSON columns
    const jobs = result.rows.map((job) => ({
      id: job.id,
      title: job.title,
      slug: job.slug,
      // Deserialize JSON strings back into JavaScript objects
      jobDetails: job.job_details_json ? JSON.parse(job.job_details_json) : {},
      jobDescription: job.description_json
        ? JSON.parse(job.description_json)
        : {},
      basicFormSchema: job.basic_form_json
        ? JSON.parse(job.basic_form_json)
        : [],
      applicationForm: job.application_form_json
        ? JSON.parse(job.application_form_json)
        : {},
    }));

    res.status(200).json({ jobs });
  } catch (error) {
    console.error("Error fetching jobs:", error);
    res.status(500).json({ error: "Failed to retrieve jobs." });
  }
});

/* ------------------ START SERVER AFTER TABLE IS READY ------------------ */

const startServer = async () => {
  await createAdminTable(); // 🔥 table is created BEFORE server starts

  const PORT = process.env.PORT || 5000;
  app.listen(PORT, () =>
    console.log(`Server running on port http://localhost:${PORT}/`)
  );
};

startServer();
