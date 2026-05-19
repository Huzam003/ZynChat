/**
 * ZynChat PostgreSQL Migration Utility
 * Migrates data from local SQLite (sql.js) to a production PostgreSQL instance.
 */

const fs = require('fs');
const { Client } = require('pg');
const initSqlJs = require('sql.js');

async function migrate() {
  const PG_CONFIG = {
    connectionString: process.env.DATABASE_URL || 'postgres://user:pass@localhost:5432/zynchat'
  };

  console.log("🚀 Starting PostgreSQL Migration...");

  // 1. Load SQLite Data
  const filebuffer = fs.readFileSync('./zynchat.db');
  const SQL = await initSqlJs();
  const db = new SQL.Database(filebuffer);

  // 2. Connect to Postgres
  const client = new Client(PG_CONFIG);
  await client.connect();

  try {
    // Create tables in Postgres
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username TEXT UNIQUE,
        password TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS messages (
        id SERIAL PRIMARY KEY,
        username TEXT,
        room TEXT,
        text TEXT,
        timestamp TEXT
      );
      CREATE TABLE IF NOT EXISTS audit_log (
        id SERIAL PRIMARY KEY,
        timestamp TEXT,
        event TEXT,
        details TEXT,
        ip TEXT,
        username TEXT
      );
    `);

    // Migrate Users
    const users = db.exec("SELECT * FROM users")[0]?.values || [];
    for (const [id, username, password] of users) {
      await client.query("INSERT INTO users (username, password) VALUES ($1, $2) ON CONFLICT DO NOTHING", [username, password]);
    }
    console.log(`✅ Migrated ${users.length} users.`);

    // Migrate Messages
    const messages = db.exec("SELECT * FROM messages")[0]?.values || [];
    for (const [id, username, room, text, timestamp] of messages) {
      await client.query("INSERT INTO messages (username, room, text, timestamp) VALUES ($1, $2, $3, $4)", [username, room, text, timestamp]);
    }
    console.log(`✅ Migrated ${messages.length} messages.`);

    console.log("🎊 Migration Successful!");
  } catch (err) {
    console.error("❌ Migration failed:", err);
  } finally {
    await client.end();
  }
}

migrate();
