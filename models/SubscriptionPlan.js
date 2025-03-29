const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const SubscriptionPlanSchema = new Schema({
  name: {
    type: String,
    required: true,
    trim: true
  },
  description: {
    type: String,
    trim: true
  },
  productId: {
    type: String,
    required: true
  },
  priceId: {
    type: String,
    required: true
  },
  amount: {
    type: Number,
    required: true
  },
  currency: {
    type: String,
    default: 'usd'
  },
  interval: {
    type: String,
    enum: ['day', 'week', 'month', 'year'],
    default: 'month'
  },
  intervalCount: {
    type: Number,
    default: 1
  },
  trialDays: {
    type: Number,
    default: 0
  },
  features: [String],
  active: {
    type: Boolean,
    default: true
  },
  createdBy: {
    type: Schema.Types.ObjectId,
    ref: 'User'
  }
}, { timestamps: true });

module.exports = mongoose.model('SubscriptionPlan', SubscriptionPlanSchema); 