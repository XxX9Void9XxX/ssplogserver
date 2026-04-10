import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import pg from "pg";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static("public"));

const { Pool } = pg;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Create table
await pool.query(`
CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL
);
`);

function auth(req, res, next) {
  const token = req.headers.authorization;
  if (!token) return res.status(401).json({ error: "No token" });

  try {
    const data = jwt.verify(token.split(" ")[1], process.env.JWT_SECRET);
    req.user = data;
    next();
  } catch {
    res.status(401).json({ error: "Invalid token" });
  }
}

// SIGNUP
app.post("/api/signup", async (req, res) => {
  const { username, password } = req.body;

  const hash = await bcrypt.hash(password, 10);

  try {
    await pool.query(
      "INSERT INTO users (username, password) VALUES ($1, $2)",
      [username, hash]
    );

    res.json({ ok: true });
  } catch {
    res.status(400).json({ error: "User exists" });
  }
});

// LOGIN
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;

  const user = await pool.query(
    "SELECT * FROM users WHERE username=$1",
    [username]
  );

  if (!user.rows[0]) return res.status(400).json({ error: "No user" });

  const valid = await bcrypt.compare(password, user.rows[0].password);
  if (!valid) return res.status(400).json({ error: "Wrong password" });

  const token = jwt.sign(
    { id: user.rows[0].id, username },
    process.env.JWT_SECRET,
    { expiresIn: "7d" }
  );

  res.json({ token });
});

// GET USER (test)
app.get("/api/me", auth, (req, res) => {
  res.json(req.user);
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log("Running on " + PORT));
