const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());
app.use(express.static('public'));

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { require: true }
});

// Middleware to verify if a user is logged in
const verifyToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(403).json({ error: "No token provided" });
    
    const token = authHeader.split(' ')[1];
    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) return res.status(401).json({ error: "Unauthorized" });
        req.user = decoded;
        next();
    });
};

// Middleware to verify if the user is the Admin
const verifyAdmin = (req, res, next) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: "Admin access required" });
    next();
};

// --- SIGN UP ROUTE ---
app.post('/signup', async (req, res) => {
    const { username, email, password } = req.body;
    try {
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        await pool.query(
            "INSERT INTO users (username, email, password) VALUES ($1, $2, $3)",
            [username, email, hashedPassword]
        );

        res.status(201).json({ message: "Account created! Waiting for Admin approval." });
    } catch (err) {
        if (err.code === '23505') {
            return res.status(400).json({ error: "Username or Email is already taken." });
        }
        res.status(500).json({ error: "Server error" });
    }
});

// --- LOG IN ROUTE ---
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    // HARDCODED ADMIN CHECK
    if (username === 'script.user' && password === 'script.password') {
        const token = jwt.sign({ role: 'admin', username: 'Admin' }, process.env.JWT_SECRET, { expiresIn: '1d' });
        return res.json({ message: "Admin access granted.", token, role: 'admin' });
    }

    try {
        const userResult = await pool.query("SELECT * FROM users WHERE username = $1", [username]);
        if (userResult.rows.length === 0) return res.status(400).json({ error: "User not found" });

        const user = userResult.rows[0];
        const validPassword = await bcrypt.compare(password, user.password);
        
        if (!validPassword) return res.status(400).json({ error: "Invalid password" });
        if (!user.is_approved) return res.status(403).json({ error: "Account is pending admin approval." });
        if (user.is_banned) return res.status(403).json({ error: "This account has been banned." });

        // Update last seen for online tracking
        await pool.query("UPDATE users SET last_seen = NOW() WHERE id = $1", [user.id]);

        const token = jwt.sign({ id: user.id, username: user.username, role: 'user' }, process.env.JWT_SECRET, { expiresIn: '7d' });
        res.json({ message: "Logged in successfully!", token, role: 'user' });
    } catch (err) {
        res.status(500).json({ error: "Server error" });
    }
});

// --- HEARTBEAT ROUTE (Tracks who is online) ---
app.post('/heartbeat', verifyToken, async (req, res) => {
    if (req.user.role !== 'admin') {
        await pool.query("UPDATE users SET last_seen = NOW() WHERE id = $1", [req.user.id]);
    }
    res.sendStatus(200);
});

// --- ADMIN ROUTES ---

// Get all users and their status
app.get('/admin/users', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT id, username, email, is_approved, is_banned, 
            (last_seen > NOW() - INTERVAL '2 minutes') as is_online 
            FROM users ORDER BY id DESC
        `);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: "Database error" });
    }
});

// Perform Admin Actions (Approve, Ban, Unban)
app.post('/admin/action', verifyToken, verifyAdmin, async (req, res) => {
    const { userId, action } = req.body;
    try {
        if (action === 'approve') await pool.query("UPDATE users SET is_approved = TRUE WHERE id = $1", [userId]);
        if (action === 'ban') await pool.query("UPDATE users SET is_banned = TRUE WHERE id = $1", [userId]);
        if (action === 'unban') await pool.query("UPDATE users SET is_banned = FALSE WHERE id = $1", [userId]);
        res.json({ message: "Action successful" });
    } catch (err) {
        res.status(500).json({ error: "Database error" });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
