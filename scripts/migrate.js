require("dotenv").config();
const fs = require("fs");
const path = require("path");
const { Pool } = require("pg");
async function main() {
  if (!process.env.DATABASE_URL) throw new Error("DATABASE_URL is required.");
  const pool = new Pool({connectionString:process.env.DATABASE_URL,ssl:{rejectUnauthorized:false},connectionTimeoutMillis:10000});
  try {
    const sql = fs.readFileSync(path.join(__dirname,"..","migrations","001_initial.sql"),"utf8");
    await pool.query(sql);
    console.log("Migration 001_initial.sql completed successfully.");
  } finally { await pool.end(); }
}
main().catch(e=>{console.error("Migration failed:",e.message);process.exitCode=1;});
