require("dotenv").config();
const mysql = require("mysql2/promise");

// Parse DATABASE_URL: mysql://user:password@host:port/database
const dbUrl = process.env.DATABASE_URL;
const match = dbUrl.match(/mysql:\/\/([^:]+):([^@]+)@([^:]+):(\d+)\/(.+)/);

if (!match) {
  throw new Error("Invalid DATABASE_URL format");
}

const [, user, password, host, port, database] = match;

const pool = mysql.createPool({
  host,
  port: parseInt(port),
  user,
  password,
  database,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

module.exports = pool;
