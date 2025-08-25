const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const User = require('../models/User');

// Protect routes - JWT authentication middleware
const auth = async (req, res, next) => {
    let token;

    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        try {
            token = req.headers.authorization.split(' ')[1];
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            const user = await User.findById(decoded.userId).select('-password -emailVerificationToken -passwordResetToken -passwordResetExpire');

            if (!user || !user.isActive || !user.isEmailVerified) {
                return res.status(401).json({ success: false, message: 'Not authorized or email not verified' });
            }

            req.user = user;
            await user.updateLastLogin();
            next();
        } catch (error) {
            console.error('JWT verification failed:', error.message);
            return res.status(401).json({ success: false, message: 'Not authorized, token failed' });
        }
    }

    if (!token) {
        return res.status(401).json({ success: false, message: 'Not authorized, no token' });
    }
};

// Admin access middleware
const adminAuth = async (req, res, next) => {
    if (req.user && req.user.role === 'admin') {
        next();
    } else {
        res.status(403).json({ success: false, message: 'Access denied. Admin privileges required.' });
    }
};

// Professional access middleware
const professionalAuth = async (req, res, next) => {
    if (req.user && ['admin', 'therapist', 'educator'].includes(req.user.role)) {
        next();
    } else {
        res.status(403).json({ success: false, message: 'Access denied. Professional account required.' });
    }
};

// Optional auth
const optionalAuth = async (req, res, next) => {
    let token;

    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        try {
            token = req.headers.authorization.split(' ')[1];
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            const user = await User.findById(decoded.userId).select('-password -emailVerificationToken -passwordResetToken -passwordResetExpire');

            if (user && user.isActive && user.isEmailVerified) {
                req.user = user;
                await user.updateLastLogin();
            }
        } catch (error) {
            console.log('Optional auth failed:', error.message);
        }
    }
    next();
};

// Subscription access middleware
const subscriptionAuth = (requiredPlan = 'premium') => {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({ success: false, message: 'Authentication required' });
        }

        const userPlan = req.user.subscription?.plan || 'free';
        const planHierarchy = { 'free': 0, 'premium': 1, 'professional': 2 };
        const requiredLevel = planHierarchy[requiredPlan] || 0;
        const userLevel = planHierarchy[userPlan] || 0;

        if (userLevel < requiredLevel || !req.user.subscription?.isActive) {
            return res.status(403).json({
                success: false,
                message: `${requiredPlan} subscription required`,
                requiredPlan,
                currentPlan: userPlan
            });
        }

        next();
    };
};

// Rate limit for auth routes
const authRateLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // Limit to 5 attempts per IP
    message: 'Too many authentication attempts, please try again later.'
});

module.exports = {
    auth,
    adminAuth,
    professionalAuth,
    optionalAuth,
    subscriptionAuth,
    authRateLimiter
};