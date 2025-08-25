const mongoose = require('mongoose');

const EmailSubscriptionSchema = new mongoose.Schema({
    email: {
        type: String,
        required: [true, 'Email is required'],
        unique: true,
        lowercase: true,
        match: [/^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/, 'Please provide a valid email']
    },
    isActive: { type: Boolean, default: true },
    source: { type: String, enum: ['website_footer', 'course_signup', 'resource_download', 'manual_add'], default: 'website_footer' },
    subscribedAt: { type: Date, default: Date.now },
    unsubscribedAt: { type: Date },
    unsubscribeToken: { type: String, unique: true, sparse: true },
    preferences: {
        weeklyNewsletter: { type: Boolean, default: true },
        courseAnnouncements: { type: Boolean, default: true },
        resourceUpdates: { type: Boolean, default: true },
        specialOffers: { type: Boolean, default: true }
    },
    tags: [{ type: String, trim: true }],
    metadata: { ipAddress: String, userAgent: String, referrer: String }
}, { timestamps: true });

EmailSubscriptionSchema.index({ email: 1 });
EmailSubscriptionSchema.index({ isActive: 1 });
EmailSubscriptionSchema.index({ subscribedAt: -1 });
EmailSubscriptionSchema.index({ unsubscribeToken: 1 }, { sparse: true });

EmailSubscriptionSchema.virtual('subscriptionDuration').get(function() {
    if (!this.isActive && this.unsubscribedAt) return this.unsubscribedAt - this.subscribedAt;
    return Date.now() - this.subscribedAt;
});

EmailSubscriptionSchema.methods.unsubscribe = function() {
    this.isActive = false;
    this.unsubscribedAt = new Date();
    return this.save();
};

EmailSubscriptionSchema.methods.resubscribe = function() {
    this.isActive = true;
    this.unsubscribedAt = null;
    this.subscribedAt = new Date();
    return this.save();
};

EmailSubscriptionSchema.statics.getActiveSubscribers = function() {
    return this.find({ isActive: true }).sort({ subscribedAt: -1 });
};

EmailSubscriptionSchema.statics.getSubscribersByPreference = function(preference) {
    const query = { isActive: true };
    query[`preferences.${preference}`] = true;
    return this.find(query);
};

module.exports = mongoose.model('EmailSubscription', EmailSubscriptionSchema);