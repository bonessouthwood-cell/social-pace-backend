const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
require('dotenv').config();
require('winston');

const connectDB = require('./config/database');
const authRoutes = require('./routes/auth');
const userRoutes = require('./routes/users');
const courseRoutes = require('./routes/courses');
const subscriptionRoutes = require('./routes/subscriptions');
const paymentRoutes = require('./routes/payments');

const app = express();

connectDB();

app.use(helmet());
app.use(cors({ origin: process.env.FRONTEND_URL || 'http://localhost:3000', credentials: true }));
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 100, message: 'Too many requests' }));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

app.use('/api/auth', authRoutes);
app.use('/api/users', userRoutes);
app.use('/api/courses', courseRoutes);
app.use('/api/subscriptions', subscriptionRoutes);
app.use('/api/payments', paymentRoutes);

app.get('/api/health', (req, res) => {
    res.status(200).json({ status: 'OK', message: 'API is running', timestamp: new Date().toISOString() });
});

app.use((err, req, res, next) => {
    console.error(err.stack);
    if (err.name === 'ValidationError') {
        return res.status(400).json({ success: false, message: 'Validation Error', errors: Object.values(err.errors).map(e => e.message) });
    }
    if (err.name === 'JsonWebTokenError') {
        return res.status(401).json({ success: false, message: 'Invalid token' });
    }
    if (err.code === 11000) {
        const field = Object.keys(err.keyValue)[0];
        return res.status(400).json({ success: false, message: `${field} already exists` });
    }
    res.status(500).json({ success: false, message: 'Server Error', error: process.env.NODE_ENV === 'production' ? {} : err });
});

app.use('*', (req, res) => {
    res.status(404).json({ success: false, message: 'API endpoint not found' });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`🚀 API running on port ${PORT}`);
    console.log(`📚 Environment: ${process.env.NODE_ENV || 'development'}`);
});