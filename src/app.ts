import express from 'express';
import dotenv from 'dotenv';
import connectDB from './config/db';
import authRoutes from './routes/authRoutes';
import { apiLimiter } from './middleware/rateLimiter';

dotenv.config();
connectDB();

const app = express();
app.use(express.json());

app.use('/auth', authRoutes);
app.use('/api/', apiLimiter);

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
