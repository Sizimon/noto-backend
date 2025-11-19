import { Router } from 'express';
import rateLimit from 'express-rate-limit';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import pool from '../db/dbConnection.js';
import { authMiddleware } from '../AuthMiddleware.js';
dotenv.config();
const LoginAndRegisterLimiter = rateLimit({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 15, // Limit each IP to 15 requests per windowMs
    message: {
        error: 'Too many login or registration attempts from this IP, please try again later.'
    }
});
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
    throw new Error('JWT_SECRET is not defined in environment variables');
}
const router = Router();
// Endpoint to register & authenticate a new user
router.post('/auth/register', LoginAndRegisterLimiter, async (req, res) => {
    try {
        const { username, email, password } = req.body;
        if (!username || !email || !password) {
            res.status(400).json({ error: 'Username, email, and password are required' });
            return;
        }
        // Check if user exists
        const existingUser = await pool.query('SELECT * FROM users WHERE username = $1 OR email = $2', [username, email]);
        if (existingUser.rows.length > 0) {
            res.status(400).json({ error: 'User already exists' });
            return;
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const result = await pool.query('INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3) RETURNING *', [username, email, hashedPassword]);
        const user = result.rows[0];
        const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '24h' });
        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production', // Only send cookie over HTTPS in production
            sameSite: 'lax', // Or 'strict' for more security
            maxAge: 24 * 60 * 60 * 1000 // 24 hours
        });
        res.status(201).json({
            message: 'User registered & authenticated successfully',
        });
    }
    catch (error) {
        console.error('Error registering user:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});
// Endpoint to authenticate user login
router.post('/auth/login', LoginAndRegisterLimiter, async (req, res) => {
    try {
        const { usernameOrEmail, password } = req.body;
        const userQuery = await pool.query('SELECT * FROM users WHERE username = $1 OR email = $2', [usernameOrEmail, usernameOrEmail]);
        const user = userQuery.rows[0];
        if (!user) {
            res.status(401).json({ error: 'Invalid username or email' });
            return;
        }
        const isPasswordValid = await bcrypt.compare(password, user.password_hash);
        if (!isPasswordValid) {
            res.status(401).json({ error: 'Invalid password' });
            return;
        }
        const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '24h' });
        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production', // Only send cookie over HTTPS in production
            sameSite: 'lax', // Or 'strict' for more security
            maxAge: 24 * 60 * 60 * 1000 // 24 hours
        });
        res.status(200).json({
            message: 'Authenticated',
        });
    }
    catch (error) {
        console.error('Error authenticating user:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});
router.get('/auth/me', authMiddleware, LoginAndRegisterLimiter, async (req, res) => {
    const userId = req.user?.id;
    if (!userId) {
        res.status(401).json({ error: 'Unauthorized' });
        return;
    }
    const userQuery = await pool.query('SELECT id, username, email, last_viewed_tasks FROM users WHERE id = $1', [userId]);
    const user = userQuery.rows[0];
    if (!user) {
        res.status(404).json({ error: 'User not found' });
        return;
    }
    res.status(200).json({
        user: {
            id: user.id,
            username: user.username,
            email: user.email,
            lastViewedTasks: user.last_viewed_tasks
        }
    });
});
router.post('/auth/logout', (req, res) => {
    res.clearCookie('token', {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
    });
    res.status(200).json({ message: 'Logged out successfully' });
});
export default router;
