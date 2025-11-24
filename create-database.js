require("dotenv").config();
const mysql = require("mysql2/promise");

async function createDatabase() {
  // Parse DATABASE_URL to get connection without database
  const dbUrl = process.env.DATABASE_URL;
  const match = dbUrl.match(/mysql:\/\/([^:]+):([^@]+)@([^:]+):(\d+)\/(.+)/);
  
  if (!match) {
    console.error("Invalid DATABASE_URL format");
    process.exit(1);
  }

  const [, user, password, host, port, database] = match;

  try {
    // Connect without specifying database
    const connection = await mysql.createPool({
      host,
      port: parseInt(port),
      user,
      password,
    });

    console.log("Connected to MySQL server");

    // Create database if it doesn't exist
    await connection.query(`CREATE DATABASE IF NOT EXISTS \`${database}\``);
    console.log(`✅ Database '${database}' created or already exists`);

    await connection.end();
    console.log("Done! You can now run 'npm run dev'");
  } catch (error) {
    console.error("❌ Error creating database:", error.message);
    process.exit(1);
  }
}

createDatabase();
