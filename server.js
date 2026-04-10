const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

// Tell the server to display your HTML files from the 'public' folder
app.use(express.static('public'));

// Connect to Neon Database using environment variables
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { require: true }
});

// --- SIGN UP ROUTE ---
app.post('/signup', async (req, res) => {
    const { username, password } = req.body;
    try {
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const newUser = await pool.query(
            "INSERT INTO users (username, password) VALUES ($1, $2) RETURNING id, username",
            [username, hashedPassword]
        );

        res.status(201).json({ message: "User created! You can now log in." });
    } catch (err) {
        if (err.code === '23505') return res.status(400).json({ error: "Username taken" });
        res.status(500).json({ error: "Server error" });
    }
});

// --- LOG IN ROUTE ---
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const userResult = await pool.query("SELECT * FROM users WHERE username = $1", [username]);
        if (userResult.rows.length === 0) return res.status(400).json({ error: "User not found" });

        const user = userResult.rows[0];

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(400).json({ error: "Invalid password" });

        // Generate the token that survives across devices
        const token = jwt.sign({ id: user.id, username: user.username }, process.env.JWT_SECRET, { expiresIn: '7d' });

        res.json({ message: "Logged in successfully!", token });
    } catch (err) {
        res.status(500).json({ error: "Server error" });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
