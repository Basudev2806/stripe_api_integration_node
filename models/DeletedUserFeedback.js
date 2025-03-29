const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const DeletedUserFeedbackSchema = new Schema({
  reason: {
    type: String,
    required: true
  },
  hadSubscription: {
    type: Boolean,
    default: false
  },
  email: {
    type: String, // Anonymized email
    required: true
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

module.exports = mongoose.model('DeletedUserFeedback', DeletedUserFeedbackSchema); 