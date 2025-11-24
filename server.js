require("dotenv").config();
const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const pool = require("./db"); // your mysql2/promise pool instance
const cookieParser = require("cookie-parser");
const { v4: uuidv4 } = require("uuid");
const multer = require("multer");
const path = require("path");
const fs = require("fs");

const app = express();

app.use(express.json());
app.use(cookieParser());
app.use(
  cors({
    origin: ["https://admin-page-steel-three.vercel.app", "http://localhost:5173"],
    credentials: true,
  })  
);

// Serve static files (uploads)
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

// --- Multer Config ---
const uploadDir = path.join(__dirname, "uploads/resumes");
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    // Sanitize filename and append timestamp
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
    cb(null, uniqueSuffix + path.extname(file.originalname));
  },
});

const upload = multer({
  storage: storage,
  fileFilter: (req, file, cb) => {
    if (file.mimetype === "application/pdf") {
      cb(null, true);
    } else {
      cb(new Error("Only PDF files are allowed!"), false);
    }
  },
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
});

// Helper: safe JSON parse (works whether DB returns string or already-parsed object)
const safeParse = (val, fallback = {}) => {
  try {
    if (val === null || val === undefined) return fallback;
    if (typeof val === "object") return val;
    if (typeof val === "string") return val === "" ? fallback : JSON.parse(val);
    return fallback;
  } catch (err) {
    console.warn("safeParse failed, returning fallback", err);
    return fallback;
  }
};

/* ------------------ CREATE TABLES (if missing) ------------------ */
const createTables = async () => {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS admin_users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        uuid VARCHAR(100) NOT NULL UNIQUE,
        full_name VARCHAR(100) NOT NULL,
        email VARCHAR(150) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL,
        role VARCHAR(20) NOT NULL DEFAULT 'admin',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS job_posts (
        id INT AUTO_INCREMENT PRIMARY KEY,
        uuid VARCHAR(100) NOT NULL UNIQUE,
        job_title VARCHAR(255) NOT NULL,
        slug VARCHAR(255) NOT NULL UNIQUE,
        details JSON NOT NULL,
        description JSON NOT NULL,
        created_by INT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      )
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS job_application_forms (
            id INT AUTO_INCREMENT PRIMARY KEY,
            uuid CHAR(36) NOT NULL,                     -- unique id for each form
            job_post_id INT NOT NULL,                   -- FK → job_posts.id
            basicFormSchema JSON NOT NULL,              -- stores array of basic form fields
            applicationFormSchema JSON NOT NULL,        -- stores array+steps for dynamic application form
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

            FOREIGN KEY (job_post_id) REFERENCES job_posts(id) ON DELETE CASCADE,
            UNIQUE KEY uniq_form_uuid (uuid)
        );
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS applicants (
            id INT AUTO_INCREMENT PRIMARY KEY,
            uuid CHAR(36) NOT NULL,                         -- unique applicant id
            job_id INT NOT NULL,                       -- FK → job_posts.id
            
            basicFormData JSON NOT NULL,                    -- applicant submitted basic fields (array)
            applicationFormData JSON NOT NULL,              -- applicant submitted step-wise answers (object)
            
            resume_path VARCHAR(255),                       -- applicant resume file path

            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

            FOREIGN KEY (job_id) REFERENCES job_posts(id) ON DELETE CASCADE,
            UNIQUE KEY uniq_applicant_uuid (uuid)
        );
    `);

    await pool.query(`
  CREATE TABLE IF NOT EXISTS shortlisted_candidates (
      id INT AUTO_INCREMENT PRIMARY KEY,
      job_post_id INT NOT NULL,
      applicant_id INT NOT NULL,

      full_name VARCHAR(255) NOT NULL,
      email VARCHAR(255) NOT NULL,
      phone VARCHAR(50),

      rating INT DEFAULT 0,
      status VARCHAR(50) DEFAULT 'New Application',
      stage VARCHAR(100) NOT NULL DEFAULT 'Application Screening',
      note TEXT,

      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

      FOREIGN KEY (job_post_id) REFERENCES job_posts(id) ON DELETE CASCADE,
      FOREIGN KEY (applicant_id) REFERENCES applicants(id) ON DELETE CASCADE
  );
`);

    // Migration: Add note column if it doesn't exist
    try {
      await pool.query("ALTER TABLE shortlisted_candidates ADD COLUMN note TEXT");
    } catch (err) {
      // Ignore error if column already exists (Error 1060: Duplicate column name)
      if (err.errno !== 1060) {
        console.warn("Warning: Could not add 'note' column:", err.message);
      }
    }

    console.log("✔ Tables ready");
  } catch (err) {
    console.error("❌ Table creation error:", err);
    process.exit(1);
  }
};

/* ------------------ AUTH MIDDLEWARE ------------------ */
const authenticateUser = (req, res, next) => {
  try {
    const authHeader = req.headers["authorization"];
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ error: "No token provided" });
    }

    const token = authHeader.split(" ")[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET || "dev-secret");

    const finalRole =
      decoded.role && decoded.role.trim() !== "" ? decoded.role : "admin";

    req.user = {
      id: decoded.id,
      uuid: decoded.uuid,
      role: finalRole,
    };

    next();
  } catch (err) {
    console.error("Auth Error:", err.message);
    return res.status(401).json({ error: "Invalid or expired token" });
  }
};

/* ------------------ AUTH ROUTES ------------------ */
app.post("/signup", async (req, res) => {
  const { full_name, email, password } = req.body;
  try {
    const passwordRegex =
      /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*])[A-Za-z\d!@#$%^&*]{8,}$/;
    if (!passwordRegex.test(password)) {
      return res
        .status(400)
        .json({ error: "Password must meet complexity rules" });
    }

    const [existing] = await pool.query(
      "SELECT id FROM admin_users WHERE email = ?",
      [email]
    );
    if (existing.length > 0)
      return res.status(400).json({ error: "Admin already exists" });

    const hashedPassword = await bcrypt.hash(password, 10);
    const uuid = uuidv4();

    await pool.query(
      "INSERT INTO admin_users (uuid, full_name, email, password) VALUES (?, ?, ?, ?)",
      [uuid, full_name, email, hashedPassword]
    );

    return res.json({ message: "Admin registered successfully" });
  } catch (err) {
    console.error("Register Error:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const [rows] = await pool.query(
      "SELECT id, uuid, full_name, email, password, role FROM admin_users WHERE email = ?",
      [email]
    );

    if (rows.length === 0)
      return res.status(400).json({ error: "Admin not found" });

    const admin = rows[0];
    const match = await bcrypt.compare(password, admin.password);
    if (!match) return res.status(400).json({ error: "Invalid password" });

    const finalRole =
      admin.role && admin.role.trim() !== "" ? admin.role : "admin";
    const token = jwt.sign(
      { id: admin.id, uuid: admin.uuid, role: finalRole },
      process.env.JWT_SECRET || "dev-secret",
      { expiresIn: "7d" }
    );

    return res.json({
      message: "Login successful",
      token,
      user: {
        id: admin.id,
        uuid: admin.uuid,
        name: admin.full_name,
        email: admin.email,
        role: finalRole,
      },
    });
  } catch (err) {
    console.error("Login error:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

/* ------------------ ADMIN USERS (CRUD) ------------------ */
app.get("/", authenticateUser, async (req, res) => {
  try {
    const [rows] = await pool.query(
      "SELECT id, full_name AS name, email, role FROM admin_users ORDER BY id DESC"
    );
    return res.status(200).json({ success: true, users: rows });
  } catch (err) {
    console.error("Error fetching users:", err);
    return res
      .status(500)
      .json({
        success: false,
        error: "Internal server error while fetching users",
      });
  }
});

app.post("/add-user", authenticateUser, async (req, res) => {
  const { name, email, role } = req.body;
  if (!name || !email || !role)
    return res.status(400).json({ message: "All fields required" });

  try {
    const [existing] = await pool.query(
      "SELECT * FROM admin_users WHERE email = ?",
      [email]
    );
    if (existing.length > 0)
      return res.status(400).json({ message: "User already exists" });

    const defaultPassword = "Password@123";
    const hashedPassword = await bcrypt.hash(defaultPassword, 10);
    const id = uuidv4();

    const [result] = await pool.query(
      "INSERT INTO admin_users (full_name, email, password, role, uuid) VALUES (?, ?, ?, ?, ?)",
      [name, email, hashedPassword, role, id]
    );

    const newUser = { id: result.insertId, name, email, role };
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
    if (result.affectedRows === 0)
      return res
        .status(404)
        .json({ success: false, message: "User not found" });
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

app.patch("/update-user/:id", authenticateUser, async (req, res) => {
  const { id } = req.params;
  const { name, email } = req.body;
  if (!name && !email)
    return res
      .status(400)
      .json({ error: "At least one field (name or email) must be provided" });

  try {
    const updateFields = [];
    const values = [];
    if (name) {
      updateFields.push("full_name = ?");
      values.push(name);
    }
    if (email) {
      updateFields.push("email = ?");
      values.push(email);
    }
    values.push(id);

    const query = `UPDATE admin_users SET ${updateFields.join(
      ", "
    )} WHERE id = ?`;
    const [result] = await pool.query(query, values);
    if (result.affectedRows === 0)
      return res.status(404).json({ error: "User not found" });

    return res.json({ message: "User updated successfully" });
  } catch (err) {
    console.error("Update User Error:", err);
    if (err.code === "ER_DUP_ENTRY")
      return res.status(409).json({ error: "Email is already in use" });
    return res.status(500).json({ error: "Internal server error" });
  }
});

app.patch("/update-password/:id", authenticateUser, async (req, res) => {
  const { id } = req.params;
  const { currentPassword, newPassword } = req.body;
  try {
    if (!currentPassword || !newPassword)
      return res.status(400).json({ error: "All fields are required" });
    const [rows] = await pool.query(
      "SELECT id, password FROM admin_users WHERE id = ?",
      [id]
    );
    if (rows.length === 0)
      return res.status(404).json({ error: "User not found" });

    const user = rows[0];
    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch)
      return res.status(401).json({ error: "Current password is incorrect" });

    const hashedPassword = await bcrypt.hash(newPassword, 10);
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

/* ------------------ JOBS API ------------------ */

// GET all jobs - returns details & description as JSON objects (not strings)
app.get("/jobs", async (req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT p.id, p.uuid, p.job_title, p.slug, p.details, p.description, p.created_at, p.updated_at, 
             f.basicFormSchema, f.applicationFormSchema
      FROM job_posts p
      LEFT JOIN job_application_forms f ON p.id = f.job_post_id
      ORDER BY p.id DESC
    `);

    console.log(rows);

    const jobs = rows.map((row) => ({
      id: row.id,
      uuid: row.uuid,
      job_title: row.job_title,
      slug: row.slug,
      details: safeParse(row.details, {}),
      description: safeParse(row.description, {}),
      basicFormSchema: row.basicFormSchema
        ? safeParse(row.basicFormSchema, [])
        : [],
      applicationFormSchema: row.applicationFormSchema
        ? safeParse(row.applicationFormSchema, {})
        : {},
      created_at: row.created_at,
      updated_at: row.updated_at,
    }));

    return res.json({ success: true, jobs });
  } catch (err) {
    console.error("Error GET /jobs:", err);
    return res
      .status(500)
      .json({ success: false, error: "Internal server error" });
  }
});

app.post("/add-job", authenticateUser, async (req, res) => {
  const connection = await pool.getConnection();
  await connection.beginTransaction();

  try {
    const jobUUID = uuidv4();
    const adminId = req.user.id;

    // Log the incoming request body for debugging
    console.log("📥 Received request body:", JSON.stringify(req.body, null, 2));

    const {
      title,
      slug,
      details,
      description,
      basicFormSchema,
      applicationForm,
      applicationFormSchema  // NEW FORMAT
    } = req.body;

    // Validate required fields
    if (!title || !slug) {
      await connection.rollback();
      return res.status(400).json({
        success: false,
        error: "Missing required fields: title and slug are required"
      });
    }

    // 1️⃣ INSERT JOB
    const [jobResult] = await connection.query(
      `INSERT INTO job_posts (uuid, job_title, slug, details, description, created_by)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [
        jobUUID,
        title,
        slug,
        JSON.stringify(details || {}),
        JSON.stringify(description || {}),
        adminId
      ]
    );

    const jobId = jobResult.insertId;

    // 2️⃣ INSERT FORM SCHEMA
    // Frontend might send as 'applicationForm' or 'applicationFormSchema'
    const formSchemaToStore = applicationFormSchema || applicationForm || {};
    
    await connection.query(
      `INSERT INTO job_application_forms (uuid, job_post_id, basicFormSchema, applicationFormSchema)
       VALUES (?, ?, ?, ?)`,
      [
        uuidv4(),
        jobId,
        JSON.stringify(basicFormSchema || []),
        JSON.stringify(formSchemaToStore)
      ]
    );

    await connection.commit();

    return res.status(201).json({
      success: true,
      message: "Job created successfully!",
      job: {
        id: jobId,
        uuid: jobUUID,
        job_title: title,
        slug,
        details,
        description,
        basicFormSchema,
        applicationFormSchema: formSchemaToStore
      }
    });
  } catch (err) {
    await connection.rollback();
    console.error(err);
    return res.status(500).json({ success: false, error: err.message });
  } finally {
    connection.release();
  }
});



// PATCH update job
app.patch("/jobs/:id", authenticateUser, async (req, res) => {
  const { id } = req.params;
  const {
    title,
    slug,
    details,
    description,
    basicFormSchema,
    applicationFormSchema,
    applicationForm
  } = req.body;

  const connection = await pool.getConnection();
  await connection.beginTransaction();

  try {
    // 1️⃣ Fetch existing job
    const [existingRows] = await connection.query(
      "SELECT * FROM job_posts WHERE id = ?",
      [id]
    );

    if (existingRows.length === 0) {
      await connection.rollback();
      return res.status(404).json({
        success: false,
        message: "Job not found"
      });
    }

    const existing = existingRows[0];

    // 2️⃣ Prepare updated values
    const updatedTitle = title ?? existing.job_title;
    const updatedSlug = slug ?? existing.slug;
    const updatedDetails = details
      ? JSON.stringify(details)
      : existing.details;

    const updatedDescription = description
      ? JSON.stringify(description)
      : existing.description;

    // 3️⃣ Update job_posts
    await connection.query(
      `UPDATE job_posts
       SET job_title = ?, slug = ?, details = ?, description = ?
       WHERE id = ?`,
      [
        updatedTitle,
        updatedSlug,
        updatedDetails,
        updatedDescription,
        id
      ]
    );

    // 4️⃣ Update job_application_forms
    const formSchemaToUpdate = applicationFormSchema || applicationForm;
    
    await connection.query(
      `UPDATE job_application_forms
       SET basicFormSchema = ?, applicationFormSchema = ?
       WHERE job_post_id = ?`,
      [
        JSON.stringify(basicFormSchema || []),
        JSON.stringify(formSchemaToUpdate || {}),
        id
      ]
    );

    await connection.commit();

    // 5️⃣ Response object
    return res.status(200).json({
      success: true,
      message: "Job updated successfully",
      job: {
        id,
        uuid: existing.uuid,
        job_title: updatedTitle,
        slug: updatedSlug,
        details: JSON.parse(updatedDetails),
        description: JSON.parse(updatedDescription),
        basicFormSchema: basicFormSchema || [],
        applicationFormSchema: applicationFormSchema || {},
        created_at: existing.created_at,
        updated_at: new Date()
      }
    });

  } catch (error) {
    await connection.rollback();
    console.error("Error updating job:", error);

    return res.status(500).json({
      success: false,
      error: "Internal server error"
    });
  } finally {
    connection.release();
  }
});


// DELETE job
app.delete("/jobs/:id", authenticateUser, async (req, res) => {
  const { id } = req.params;

  try {
    // First check if job exists
    const [existing] = await pool.query(
      "SELECT id, uuid, job_title FROM job_posts WHERE id = ?",
      [id]
    );

    if (existing.length === 0) {
      return res.status(404).json({
        success: false,
        message: "Job not found or already deleted."
      });
    }

    // Delete the job (CASCADE will remove form schema automatically)
    const [result] = await pool.query(
      "DELETE FROM job_posts WHERE id = ?",
      [id]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({
        success: false,
        message: "Job not found or already deleted."
      });
    }

    return res.status(200).json({
      success: true,
      message: "Job deleted successfully",
      deleted: {
        id: existing[0].id,
        uuid: existing[0].uuid,
        title: existing[0].job_title
      }
    });

  } catch (error) {
    console.error("Error deleting job:", error);

    return res.status(500).json({
      success: false,
      message: "Internal server error during job deletion.",
      error: error.message
    });
  }
});


/* ------------------ APPLICANTS API ------------------ */

app.post("/applicants", upload.single("resume"), async (req, res) => {
  const connection = await pool.getConnection();
  try {
    const { job_id, basicFormData, applicationFormData } = req.body;
    const resume_path = req.file ? `/uploads/resumes/${req.file.filename}` : null;

    // Parse JSON strings if they come as strings from FormData
    const parsedBasicFormData = typeof basicFormData === 'string' 
      ? JSON.parse(basicFormData) 
      : basicFormData;
    
    const parsedApplicationFormData = typeof applicationFormData === 'string'
      ? JSON.parse(applicationFormData)
      : applicationFormData;

    // Extract full_name and email from basicFormData for validation and shortlisted_candidates
    const fullNameField = parsedBasicFormData?.find(field => 
      field.label === 'Full Name' || field.name === 'full_name' || field.name === 'fullName'
    );
    const emailField = parsedBasicFormData?.find(field => 
      field.label === 'Email' || field.name === 'email'
    );
    const phoneField = parsedBasicFormData?.find(field => 
      field.label === 'Phone' || field.name === 'phone'
    );

    const full_name = fullNameField?.value || '';
    const email = emailField?.value || '';
    const phone = phoneField?.value || '';

    if (!job_id || !full_name || !email) {
      return res.status(400).json({ 
        success: false, 
        message: "Missing required fields: job_id, full_name, and email" 
      });
    }

    if (!resume_path) {
      return res.status(400).json({ success: false, message: "Resume PDF is required" });
    }

    await connection.beginTransaction();

    // Generate UUID for applicant
    const applicantUuid = uuidv4();

    // Insert into applicants table with correct column names
    const [applicantResult] = await connection.query(
      `INSERT INTO applicants (uuid, job_id, basicFormData, applicationFormData, resume_path) 
       VALUES (?, ?, ?, ?, ?)`,
      [
        applicantUuid,
        job_id,
        JSON.stringify(parsedBasicFormData || []),
        JSON.stringify(parsedApplicationFormData || {}),
        resume_path,
      ]
    );

    const applicantId = applicantResult.insertId;

    // Insert into shortlisted_candidates
    await connection.query(
      `INSERT INTO shortlisted_candidates 
        (job_post_id, applicant_id, full_name, email, phone, rating, status, stage)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        job_id,
        applicantId,
        full_name,
        email,
        phone,
        0,
        "New Application",  
        "Application Screening"
      ]
    );


    await connection.commit();

    return res.status(201).json({
      success: true,
      message: "Application submitted & candidate shortlisted!",
      applicant_id: applicantId
    });

  } catch (error) {
    await connection.rollback();
    console.error("Error submitting application:", error);

    if (req.file) {
      fs.unlink(req.file.path, () => {});
    }

    return res.status(500).json({ 
      success: false, 
      message: "Internal server error",
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  } finally {
    connection.release();
  }
});


app.get("/applicants", authenticateUser, async (req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT 
        a.id as applicant_id,
        a.full_name,
        a.email,
        a.phone,
        a.resume_path,
        a.steps_json,
        a.fields_json,
        a.created_at,
        a.job_id,
        j.job_title,
        JSON_UNQUOTE(JSON_EXTRACT(j.details, '$.department')) AS department,
        sc.id as shortlist_id,
        sc.job_post_id,
        sc.status,
        sc.stage,
        sc.rating
      FROM applicants a
      JOIN job_posts j ON j.id = a.job_id
      LEFT JOIN shortlisted_candidates sc ON sc.applicant_id = a.id
      ORDER BY a.created_at DESC
    `);
    console.log(rows)

    const data = rows.map(r => ({
      id: r.applicant_id,
      shortlist_id: r.shortlist_id,
      full_name: r.full_name,
      email: r.email,
      phone: r.phone,
      resume_path: r.resume_path,
      job_title: r.job_title,
      job_id: r.job_id,
      job_post_id: r.job_post_id,
      department: r.department,
      currentStage: r.stage,
      currentStageStatus: r.status,
      rating: r.rating,
      applied_at: r.created_at,
      steps: safeParse(r.steps_json || r.basicFormData, []),
      fields: safeParse(r.fields_json || r.applicationFormData, {}),
    }));

    console.log(data)

    return res.json({ success: true, applicants: data });
  } catch (err) {
    console.error("/applicants/new Error:", err);
    return res.status(500).json({ success: false });
  }
});

app.get("/applicants/shortlisted", authenticateUser, async (req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT 
        sc.*, 
        j.job_title,
        JSON_UNQUOTE(JSON_EXTRACT(j.details, '$.department')) AS department,
        a.resume_path,
        a.basicFormData,
        a.applicationFormData,
        a.steps_json,
        a.fields_json
      FROM shortlisted_candidates sc
      JOIN applicants a ON a.id = sc.applicant_id
      JOIN job_posts j ON j.id = sc.job_post_id
      WHERE sc.status = 'Shortlisted'
      ORDER BY sc.created_at DESC
    `);

    const data = rows.map(r => ({
      id: r.id,
      full_name: r.full_name,
      email: r.email,
      phone: r.phone,
      job_title: r.job_title,
      department: r.department,
      status: r.status,
      stage: r.stage,
      rating: r.rating,
      resume_path: r.resume_path,
      steps: safeParse(r.steps_json || r.basicFormData, []),
      fields: safeParse(r.fields_json || r.applicationFormData, {}),
    }));

    return res.json({ success: true, applicants: data });
  } catch (err) {
    console.error("/applicants/shortlisted Error:", err);
    return res.status(500).json({ success: false });
  }
});

app.get("/applicants/rejected", authenticateUser, async (req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT 
        sc.*, 
        j.job_title,
        JSON_UNQUOTE(JSON_EXTRACT(j.details, '$.department')) AS department,
        a.resume_path
      FROM shortlisted_candidates sc
      JOIN applicants a ON a.id = sc.applicant_id
      JOIN job_posts j ON j.id = sc.job_post_id
      WHERE sc.status = 'Rejected'
      ORDER BY sc.created_at DESC
    `);

    const data = rows.map(r => ({
      id: r.id,
      full_name: r.full_name,
      email: r.email,
      phone: r.phone,
      job_title: r.job_title,
      department: r.department,
      status: "Rejected",
      stage: r.stage,
      resume_path: r.resume_path,
    }));

    return res.json({ success: true, applicants: data });
  } catch (err) {
    console.error("/applicants/rejected Error:", err);
    return res.status(500).json({ success: false });
  }
});


app.get("/applicants/hired", authenticateUser, async (req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT 
        sc.*, 
        j.job_title,
        JSON_UNQUOTE(JSON_EXTRACT(j.details, '$.department')) AS department,
        a.resume_path
      FROM shortlisted_candidates sc
      JOIN applicants a ON a.id = sc.applicant_id
      JOIN job_posts j ON j.id = sc.job_post_id
      WHERE sc.status = 'Hired'
      ORDER BY sc.created_at DESC
    `);

    const data = rows.map(r => ({
      id: r.id,
      full_name: r.full_name,
      email: r.email,
      phone: r.phone,
      job_title: r.job_title,
      department: r.department,
      status: "Hired",
      stage: r.stage,
      rating: r.rating,
      resume_path: r.resume_path,
    }));

    return res.json({ success: true, applicants: data });
  } catch (err) {
    console.error("/applicants/hired Error:", err);
    return res.status(500).json({ success: false });
  }
});




// PATCH /applicants/:id/stage - Update stage/status/note (Admin)
app.patch("/applicants/:id/stage", authenticateUser, async (req, res) => {
  const { id } = req.params;
  const { stageId, status, note } = req.body;

  try {
    // First, check if the applicant exists in shortlisted_candidates
    const [existing] = await pool.query(
      "SELECT id FROM shortlisted_candidates WHERE applicant_id = ?",
      [id]
    );

    // If not in shortlisted_candidates, create the entry first
    if (existing.length === 0) {
      // Get applicant data to create shortlisted_candidates entry
      const [applicantData] = await pool.query(
        "SELECT job_id, full_name, email, phone FROM applicants WHERE id = ?",
        [id]
      );

      if (applicantData.length === 0) {
        return res.status(404).json({ success: false, message: "Applicant not found" });
      }

      const applicant = applicantData[0];
      
      // Create shortlisted_candidates entry
      await pool.query(
        `INSERT INTO shortlisted_candidates 
          (job_post_id, applicant_id, full_name, email, phone, rating, status, stage)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          applicant.job_id,
          id,
          applicant.full_name,
          applicant.email,
          applicant.phone,
          0,
          "New Application",
          "Application Screening"
        ]
      );
    }

    // Now update shortlisted_candidates based on applicant_id (which is :id)
    // We assume stageId maps to 'stage' column
    const updateFields = [];
    const values = [];

    if (stageId !== undefined) {
      updateFields.push("stage = ?");
      values.push(stageId);
    }
    if (status !== undefined) {
      updateFields.push("status = ?");
      values.push(status);
    }
    if (note !== undefined) {
      updateFields.push("note = ?");
      values.push(note);
    }

    if (updateFields.length === 0) {
      return res.status(400).json({ success: false, message: "No fields to update" });
    }

    values.push(id);

    const query = `UPDATE shortlisted_candidates SET ${updateFields.join(", ")} WHERE applicant_id = ?`;
    
    const [result] = await pool.query(query, values);

    if (result.affectedRows === 0) {
      return res.status(404).json({ success: false, message: "Applicant not found in shortlisted candidates" });
    }

    // Fetch the updated data to send back
    const [updatedRows] = await pool.query(`
      SELECT 
        a.id as applicant_id,
        a.full_name,
        a.email,
        a.phone,
        a.resume_path,
        a.steps_json,
        a.fields_json,
        a.created_at,
        a.job_id,
        j.job_title,
        JSON_UNQUOTE(JSON_EXTRACT(j.details, '$.department')) AS department,
        sc.id as shortlist_id,
        sc.job_post_id,
        sc.status,
        sc.stage,
        sc.rating,
        sc.note
      FROM applicants a
      JOIN job_posts j ON j.id = a.job_id
      JOIN shortlisted_candidates sc ON sc.applicant_id = a.id
      WHERE a.id = ?
    `, [id]);

    if (updatedRows.length === 0) {
      return res.status(404).json({ success: false, message: "Updated applicant not found" });
    }

    const updatedApplicant = {
      id: updatedRows[0].applicant_id,
      shortlist_id: updatedRows[0].shortlist_id,
      full_name: updatedRows[0].full_name,
      email: updatedRows[0].email,
      phone: updatedRows[0].phone,
      resume_path: updatedRows[0].resume_path,
      job_title: updatedRows[0].job_title,
      job_id: updatedRows[0].job_id,
      job_post_id: updatedRows[0].job_post_id,
      department: updatedRows[0].department,
      currentStage: updatedRows[0].stage,
      currentStageStatus: updatedRows[0].status,
      rating: updatedRows[0].rating,
      note: updatedRows[0].note,
      applied_at: updatedRows[0].created_at,
      steps: safeParse(updatedRows[0].steps_json || updatedRows[0].basicFormData, []),
      fields: safeParse(updatedRows[0].fields_json || updatedRows[0].applicationFormData, {}),
    };

    return res.json({ 
      success: true, 
      message: "Applicant stage updated successfully",
      applicant: updatedApplicant
    });
  } catch (error) {
    console.error("Error updating applicant stage:", error);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
});

// GET /applicants/:id - Get single (Admin)
app.get("/applicants/:id", authenticateUser, async (req, res) => {
  const { id } = req.params;
  try {
    const [rows] = await pool.query(`
      SELECT a.*, j.job_title 
      FROM applicants a
      JOIN job_posts j ON a.job_id = j.id
      WHERE a.id = ?
    `, [id]);

    if (rows.length === 0) {
      return res.status(404).json({ success: false, message: "Applicant not found" });
    }

    const applicant = {
      ...rows[0],
      steps_json: safeParse(rows[0].steps_json, []),
      fields_json: safeParse(rows[0].fields_json, [])
    };

    return res.json({ success: true, applicant });
  } catch (error) {
    console.error("Error fetching applicant:", error);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
});

// GET /applicants/job/:job_id - List by job (Admin)
app.get("/applicants/job/:job_id", authenticateUser, async (req, res) => {
  const { job_id } = req.params;
  try {
    const [rows] = await pool.query(`
      SELECT * FROM applicants WHERE job_id = ? ORDER BY created_at DESC
    `, [job_id]);

    const applicants = rows.map(row => ({
      ...row,
      steps_json: safeParse(row.steps_json, []),
      fields_json: safeParse(row.fields_json, [])
    }));

    return res.json({ success: true, applicants });
  } catch (error) {
    console.error("Error fetching applicants for job:", error);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
});

// DELETE /applicants/:id - Delete applicant and file (Admin)
app.delete("/applicants/:id", authenticateUser, async (req, res) => {
  const { id } = req.params;
  const connection = await pool.getConnection();
  try {
    // Get file path first
    const [rows] = await connection.query("SELECT resume_path FROM applicants WHERE id = ?", [id]);
    if (rows.length === 0) {
      return res.status(404).json({ success: false, message: "Applicant not found" });
    }

    const resumePath = rows[0].resume_path;

    // Delete from DB
    await connection.query("DELETE FROM applicants WHERE id = ?", [id]);

    // Delete file
    if (resumePath) {
      const absolutePath = path.join(__dirname, resumePath);
      if (fs.existsSync(absolutePath)) {
        fs.unlink(absolutePath, (err) => {
          if (err) console.error("Error deleting resume file:", err);
        });
      }
    }

    return res.json({ success: true, message: "Applicant deleted successfully" });
  } catch (error) {
    console.error("Error deleting applicant:", error);
    return res.status(500).json({ success: false, message: "Internal server error" });
  } finally {
    connection.release();
  }
});

/* ------------------ START SERVER ------------------ */
const startServer = async () => {
  await createTables();
  const PORT = process.env.PORT || 5000;
  app.listen(PORT, () =>
    console.log(`Server running on http://localhost:${PORT}`)
  );
};

startServer();
