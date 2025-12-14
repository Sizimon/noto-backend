import jwt from 'jsonwebtoken';
import { Request, Response, NextFunction } from 'express';
import dotenv from 'dotenv';
dotenv.config();

const JWT_SECRET = process.env.JWT_SECRET;

export function authMiddleware(req: Request, res: Response, next: NextFunction): void {
    const token = req.cookies?.token;
    // console.error('Auth Header:', authHeader);
    if (!token) {
        res.status(401).json({ error: 'Authorization token is required' });
        return;
    }

    if (!JWT_SECRET) {
        throw new Error('JWT_SECRET is not defined in environment variables');
    }
    
    try {
        const decoded = jwt.verify(token, JWT_SECRET) as { userId: number };
        req.user = { id: decoded.userId };

        // Issue a new token with 24h expiry
        const newToken = jwt.sign({ userId: decoded.userId }, JWT_SECRET, { expiresIn: '24h' });
        res.cookie('token', newToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax',
            maxAge: 24 * 60 * 60 * 1000
        });

        next();
    } catch (error) {
        res.status(401).json({ error: 'Invalid or expired token' });
    }
}