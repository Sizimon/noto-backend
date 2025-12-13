import express from 'express';
import cookieParser from 'cookie-parser';
import cors from 'cors';
import authRoutes from './routes/authRoutes.js';
import taskRoutes from './routes/taskRoutes.js';
import userRoutes from './routes/userRoutes.js';
const app = express();
app.set('trust proxy', 1); // Trust the first proxy 
app.use(cors({
    origin: 'https://szymonsamus.dev',
    credentials: true
}));
app.use(express.json());
app.use(cookieParser());
app.use('/noto-backend/api', authRoutes);
app.use('/noto-backend/api', taskRoutes);
app.use('/noto-backend/api', userRoutes);
const PORT = 5006;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server is running on port ${PORT}`);
});
