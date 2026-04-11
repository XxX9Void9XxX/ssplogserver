const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const path = require('path');

const app = express();
app.use(express.json());
app.use(cors());

// Serve frontend files
app.use(express.static(path.join(__dirname, 'public')));

// IMPORTANT: Paste your Neon Connection String inside these quotes!
// It should start with "postgresql://"
const NEON_URI = "postgresql://neondb_owner:npg_xBa02HOJktXz@ep-delicate-dream-amrk8l8h-pooler.c-5.us-east-1.aws.neon.tech/neondb?sslmode=require&channel_binding=require"; 
const SECRET_KEY = "shadow-sites-plus-super-secret-key"; 

// --- CONNECT TO NEON DATABASE ---
const pool = new Pool({
    connectionString: NEON_URI,
    ssl: { rejectUnauthorized: false } 
});

// Initialize Tables automatically
pool.query(`
    CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(255) UNIQUE NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        role VARCHAR(50) DEFAULT 'user',
        is_approved BOOLEAN DEFAULT false,
        is_banned BOOLEAN DEFAULT false,
        last_seen BIGINT DEFAULT 0,
        is_online BOOLEAN DEFAULT false
    );
`).then(() => console.log("Connected to Neon DB!"))
  .catch(err => console.error("DATABASE INITIALIZATION ERROR:", err));

// --- HELPER ROUTINE: KICK OFFLINE USERS ---
setInterval(async () => {
    const cutoff = Date.now() - 15000;
    try {
        await pool.query("UPDATE users SET is_online = false WHERE last_seen < $1 AND is_online = true", [cutoff]);
    } catch(e) {}
}, 5000);

// --- AUTHENTICATION ROUTES ---
app.post('/signup', async (req, res) => {
    const { username, email, password } = req.body;
    if (!username || !email || !password) return res.status(400).json({ error: "All fields required" });

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // Insert as a normal, unapproved user
        await pool.query(
            "INSERT INTO users (username, email, password, role, is_approved) VALUES ($1, $2, $3, 'user', false)",
            [username, email, hashedPassword]
        );

        res.json({ message: "Account created! Waiting for admin approval." });
    } catch (err) {
        console.error("SIGNUP ERROR DETAILS:", err); // <--- THIS WILL TELL US THE PROBLEM!
        if (err.code === '23505') return res.status(400).json({ error: "Username or email already exists." });
        res.status(500).json({ error: "Server error" });
    }
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    // --- SECRET ADMIN BACKDOOR ---
    if (username === 'script.user' && password === 'script.password') {
        const token = jwt.sign({ id: 999999, role: 'admin' }, SECRET_KEY, { expiresIn: '24h' });
        return res.json({ token, role: 'admin' });
    }

    // Normal User Login
    try {
        const userRes = await pool.query("SELECT * FROM users WHERE username = $1", [username]);
        const user = userRes.rows[0];

        if (!user) return res.status(400).json({ error: "Invalid username or password" });
        if (user.is_banned) return res.status(403).json({ error: "Your account is banned." });
        if (!user.is_approved) return res.status(403).json({ error: "Account pending admin approval." });

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(400).json({ error: "Invalid username or password" });

        const token = jwt.sign({ id: user.id, role: user.role }, SECRET_KEY, { expiresIn: '24h' });
        
        await pool.query("UPDATE users SET is_online = true, last_seen = $1 WHERE id = $2", [Date.now(), user.id]);
        res.json({ token, role: user.role });
    } catch (err) {
        console.error("LOGIN ERROR DETAILS:", err);
        res.status(500).json({ error: "Server error" });
    }
});

// --- HEARTBEAT ROUTE ---
app.post('/heartbeat', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: "No token" });

    jwt.verify(token, SECRET_KEY, async (err, decoded) => {
        if (err) return res.status(401).json({ error: "Session expired" });

        try {
            await pool.query("UPDATE users SET is_online = true, last_seen = $1 WHERE id = $2", [Date.now(), decoded.id]);
            res.status(200).json({ status: "ok" });
        } catch (dbErr) {
            res.status(500).json({ error: "Database error" });
        }
    });
});

app.post('/offline', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1] || req.body.token;
    if (!token) return res.status(401).end();

    jwt.verify(token, SECRET_KEY, async (err, decoded) => {
        if (!err && decoded) {
            await pool.query("UPDATE users SET is_online = false WHERE id = $1", [decoded.id]).catch(()=>{});
        }
        res.status(200).end();
    });
});

// --- ADMIN ROUTES ---
function verifyAdmin(req, res, next) {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: "Unauthorized" });

    jwt.verify(token, SECRET_KEY, (err, decoded) => {
        if (err || decoded.role !== 'admin') return res.status(403).json({ error: "Forbidden" });
        next();
    });
}

app.get('/admin/users', verifyAdmin, async (req, res) => {
    try {
        const result = await pool.query("SELECT id, username, email, role, is_approved, is_banned, is_online FROM users ORDER BY id ASC");
        res.json(result.rows);
    } catch (err) {
        console.error("ADMIN PANEL ERROR DETAILS:", err);
        res.status(500).json({ error: "Database error" });
    }
});

app.post('/admin/action', verifyAdmin, async (req, res) => {
    const { userId, action } = req.body;
    try {
        if (action === 'approve') await pool.query("UPDATE users SET is_approved = true WHERE id = $1", [userId]);
        if (action === 'ban') await pool.query("UPDATE users SET is_banned = true, is_online = false WHERE id = $1", [userId]);
        if (action === 'unban') await pool.query("UPDATE users SET is_banned = false WHERE id = $1", [userId]);
        
        res.json({ message: "Success" });
    } catch (err) {
        console.error("ADMIN ACTION ERROR DETAILS:", err);
        res.status(500).json({ error: "Database error" });
    }
});

// --- START SERVER ---
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`SSP Server running on port ${PORT}`));
