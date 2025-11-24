// routes/jobRoutes.js

const express = require("express");
const { v4: uuidv4 } = require("uuid");
const pool = require("../db"); // Adjust path as needed
const { authenticateUser } = require("./userRoutes"); // To import authenticateUser

const router = express.Router();
// Use the middleware from userRoutes to protect job routes
/* ------------------ Jobs Posts (CREATE) ------------------ */

// POST /jobs/add-jobs (You can simplify this path to just POST /)
router.post("/add-jobs", authenticateUser, async (req, res) => {
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

    await pool.query(
      `INSERT INTO jobs 
          (id, title, slug, job_details_json, description_json, basic_form_json, application_form_json, created_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, NOW())`,
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

    const postedJob = {
      id: jobId,
      title: title,
      slug: slug || null,
      jobDetails: jobDetails || {},
      jobDescription: jobDescription || {},
      basicFormSchema: basicFormSchema || [],
      applicationForm: applicationForm || {},
      createdAt: new Date().toISOString(),
    };

    return res.status(201).json({
      message: "Job Post Created successfully",
      job: postedJob,
    });
  } catch (error) {
    console.error("Error in posting a job:", error);
    return res.status(500).json({ error: "Internal server error" });
  }
});

/* ------------------ Jobs Posts (READ/LIST) ------------------ */

// GET /jobs/
router.get("/", async (req, res) => {
  try {
    // Note: Switched to pool.query, assuming your 'db' exposes this function.
    // The original code used 'db.query' but imported 'pool'. I've changed it to 'pool.query'.
    const [result] = await pool.query(
      "SELECT id, title, slug, job_details_json, description_json, basic_form_json, application_form_json FROM jobs"
    );

    // Assuming your MySQL/MariaDB driver returns an array of rows directly
    // If it returns { rows: [...] } you need to adjust 'result' to 'result.rows' or similar.
    const jobs = result.map((job) => ({
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

/* ------------------ Jobs Posts (DELETE) ------------------ */

// DELETE /jobs/:id
router.delete("/:id", authenticateUser, async (req, res) => {
  const { id } = req.params;

  try {
    const [result] = await pool.query("DELETE FROM jobs WHERE id = ?", [id]);

    if (result.affectedRows === 0) {
      return res.status(404).json({
        success: false,
        message: "Job not found or already deleted.",
      });
    }

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

// PATCH /jobs/:id
router.patch("/:id", authenticateUser, async (req, res) => {
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
    const [currentJobRows] = await pool.query(
      "SELECT * FROM jobs WHERE id = ?",
      [id]
    );

    if (currentJobRows.length === 0) {
      return res.status(404).json({ success: false, message: "Job not found" });
    }

    const currentJob = currentJobRows[0];

    let updateFields = [];
    let values = [];

    if (title !== undefined) {
      updateFields.push("title = ?");
      values.push(title);
    }
    if (slug !== undefined) {
      updateFields.push("slug = ?");
      values.push(slug);
    }

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

    values.push(id);
    const query = `UPDATE jobs SET ${updateFields.join(", ")} WHERE id = ?`;

    await pool.query(query, values);

    // Construct and return the UPDATED job object (deserializing JSON columns)
    const updatedJob = {
      id: currentJob.id,
      title: title || currentJob.title,
      slug: slug || currentJob.slug,

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

module.exports = router;
