const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const UserSchema = new mongoose.Schema({
    name: { type: String, required: [true, 'Name is required'], trim: true, maxlength: [100, 'Name cannot exceed 100 characters'] },
    email: { type: String, required: [true, 'Email is required'], unique: true, lowercase: true, match: [/^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/, 'Invalid email'] },
    password: { type: String, required: [true, 'Password is required'], minlength: [6, 'Password must be at least 6 characters'], select: false },
    role: { type: String, enum: ['parent', 'educator', 'therapist', 'other'], required: [true, 'Role is required'] },
    isEmailVerified: { type: Boolean, default: false },
    emailVerificationToken: String,
    passwordResetToken: String,
    passwordResetExpire: Date,
    profile: { avatar: String, bio: String, location: String, website: String, linkedin: String, specializations: [String] },
    enrolledCourses: [{
        courseId: { type: mongoose.Schema.Types.ObjectId, ref: 'Course' },
        enrolledAt: { type: Date, default: Date.now },
        progress: { type: Number, default: 0, min: 0, max: 100 },
        completedLessons: [{ lessonId: String, completedAt: Date }],
        completedAt: Date,
        certificateIssued: { type: Boolean, default: false }
    }],
    subscription: { isActive: { type: Boolean, default: false }, plan: { type: String, enum: ['free', 'premium', 'professional'], default: 'free' }, startDate: Date, endDate: Date, stripeCustomerId: String, stripeSubscriptionId: String },
    preferences: { emailNotifications: { type: Boolean, default: true }, marketingEmails: { type: Boolean, default: true }, courseReminders: { type: Boolean, default: true } },
    lastLogin: Date,
    isActive: { type: Boolean, default: true }
}, { timestamps: true, toJSON: { virtuals: true }, toObject: { virtuals: true } });

UserSchema.virtual('completedCoursesCount').get(function() { return this.enrolledCourses.filter(c => c.completedAt).length; });
UserSchema.virtual('totalLearningHours').get(function() { return this.enrolledCourses.length * 4; });

UserSchema.index({ email: 1 }, { unique: true });
UserSchema.index({ 'enrolledCourses.courseId': 1 });
UserSchema.index({ createdAt: -1 });

UserSchema.pre('save', async function(next) {
    if (!this.isModified('password')) return next();
    const salt = await bcrypt.genSalt(12);
    this.password = await bcrypt.hash(this.password, salt);
    next();
});

UserSchema.methods.updateLastLogin = function() {
    this.lastLogin = new Date();
    return this.save({ validateBeforeSave: false });
};

UserSchema.methods.comparePassword = async function(candidatePassword) {
    return await bcrypt.compare(candidatePassword, this.password);
};

UserSchema.methods.getEnrolledCourse = function(courseId) {
    return this.enrolledCourses.find(c => c.courseId.toString() === courseId.toString());
};

UserSchema.methods.enrollInCourse = function(courseId) {
    if (this.getEnrolledCourse(courseId)) throw new Error('Already enrolled');
    this.enrolledCourses.push({ courseId, enrolledAt: new Date(), progress: 0 });
    return this.save();
};

UserSchema.methods.updateCourseProgress = function(courseId, lessonId) {
    const enrollment = this.getEnrolledCourse(courseId);
    if (!enrollment) throw new Error('Not enrolled');
    if (!enrollment.completedLessons.some(l => l.lessonId === lessonId)) {
        enrollment.completedLessons.push({ lessonId, completedAt: new Date() });
        enrollment.progress = Math.min(100, enrollment.progress + 10);
        if (enrollment.progress >= 100 && !enrollment.completedAt) enrollment.completedAt = new Date();
    }
    return this.save();
};

module.exports = mongoose.model('User', UserSchema);