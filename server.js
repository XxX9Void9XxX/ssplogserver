const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const path = require('path');

const app = express();
app.use(express.json());
app.use(cors());

// Serve your frontend files from a folder called "public"
app.use(express.static(path.join(__dirname, 'public')));

// IMPORTANT: Change this to a random long string in production
const SECRET_KEY = "shadow-sites-plus-super-secret-key"; 

// --- DATABASE SETUP ---
// Creates a local SQLite database file named "database.sqlite"
const db = new sqlite3.Database('./database.sqlite');

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        email TEXT UNIQUE,
        password TEXT,
        role TEXT DEFAULT 'user',
        is_approved BOOLEAN DEFAULT 0,
        is_banned BOOLEAN DEFAULT 0,
        last_seen INTEGER DEFAULT 0,
        is_online BOOLEAN DEFAULT 0
    )`);
});

// --- HELPER ROUTINE: KICK OFFLINE USERS ---
// Runs every 5 seconds. If a user hasn't pinged the heartbeat in 15 seconds, mark offline.
setInterval(() => {
    const cutoff = Date.now() - 15000;
    db.run("UPDATE users SET is_online = 0 WHERE last_seen < ? AND is_online = 1", [cutoff]);
}, 5000);

// --- AUTHENTICATION ROUTES ---

app.post('/signup', async (req, res) => {
    const { username, email, password } = req.body;
    if (!username || !email || !password) {
        return res.status(400).json({ error: "All fields are required" });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // Check if this is the very first user. If it is, make them an Admin automatically.
        db.get("SELECT COUNT(*) as count FROM users", (err, row) => {
            const isFirstUser = row.count === 0;
            const role = isFirstUser ? 'admin' : 'user';
            const isApproved = isFirstUser ? 1 : 0; // First user is auto-approved

            db.run(
                "INSERT INTO users (username, email, password, role, is_approved) VALUES (?, ?, ?, ?, ?)",
                [username, email, hashedPassword, role, isApproved],
                function(err) {
                    if (err) return res.status(400).json({ error: "Username or email already exists." });
                    res.json({ message: "Account created! " + (isFirstUser ? "You are the admin." : "Waiting for admin approval.") });
                }
            );
        });
    } catch (err) {
        res.status(500).json({ error: "Server error" });
    }
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;

    db.get("SELECT * FROM users WHERE username = ?", [username], async (err, user) => {
        if (err || !user) return res.status(400).json({ error: "Invalid username or password" });
        
        if (user.is_banned) return res.status(403).json({ error: "Your account is banned." });
        if (!user.is_approved) return res.status(403).json({ error: "Account pending admin approval." });

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(400).json({ error: "Invalid username or password" });

        const token = jwt.sign({ id: user.id, role: user.role }, SECRET_KEY, { expiresIn: '24h' });
        
        // Mark as online immediately upon login
        db.run("UPDATE users SET is_online = 1, last_seen = ? WHERE id = ?", [Date.now(), user.id]);

        res.json({ token, role: user.role });
    });
});

// --- THE INSTANT BAN FIX: HEARTBEAT ROUTE ---
app.post('/heartbeat', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: "No token" });

    jwt.verify(token, SECRET_KEY, (err, decoded) => {
        if (err) return res.status(401).json({ error: "Invalid token" });

        const userId = decoded.id;

        // THE FIX: Actually check the database to see if an admin banned them
        db.get("SELECT is_banned FROM users WHERE id = ?", [userId], (err, user) => {
            if (err || !user) return res.status(401).json({ error: "User not found" });
            
            // If the database says they are banned, send 403 Forbidden to trigger the frontend kick
            if (user.is_banned) {
                db.run("UPDATE users SET is_online = 0 WHERE id = ?", [userId]);
                return res.status(403).json({ error: "banned" }); 
            }

            // Otherwise, update their last seen timestamp
            db.run("UPDATE users SET is_online = 1, last_seen = ? WHERE id = ?", [Date.now(), userId]);
            res.status(200).json({ status: "ok" });
        });
    });
});

app.post('/offline', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1] || req.body.token;
    if (!token) return res.status(401).end();

    jwt.verify(token, SECRET_KEY, (err, decoded) => {
        if (!err && decoded) {
            db.run("UPDATE users SET is_online = 0 WHERE id = ?", [decoded.id]);
        }
        res.status(200).end();
    });
});

// --- ADMIN ROUTES ---
// Middleware to protect admin routes
function verifyAdmin(req, res, next) {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: "Unauthorized" });

    jwt.verify(token, SECRET_KEY, (err, decoded) => {
        if (err || decoded.role !== 'admin') return res.status(403).json({ error: "Forbidden" });
        next();
    });
}

app.get('/admin/users', verifyAdmin, (req, res) => {
    db.all("SELECT id, username, email, role, is_approved, is_banned, is_online FROM users", [], (err, rows) => {
        if (err) return res.status(500).json({ error: "Database error" });
        res.json(rows);
    });
});

app.post('/admin/action', verifyAdmin, (req, res) => {
    const { userId, action } = req.body;

    let query = "";
    if (action === 'approve') query = "UPDATE users SET is_approved = 1 WHERE id = ?";
    if (action === 'ban') query = "UPDATE users SET is_banned = 1, is_online = 0 WHERE id = ?";
    if (action === 'unban') query = "UPDATE users SET is_banned = 0 WHERE id = ?";

    if (query) {
        db.run(query, [userId], (err) => {
            if (err) return res.status(500).json({ error: "Database error" });
            res.json({ message: "Success" });
        });
    } else {
        res.status(400).json({ error: "Invalid action" });
    }
});

// --- START SERVER ---
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`SSP Server running on port ${PORT}`);
});
