// // models/User.js
// const mongoose = require('mongoose');
//
// // Define schema for User
// const userSchema = new mongoose.Schema({
//   email: { type: String, required: true, unique: true },
//   password: { type: String, required: true },
//   customerId: { type: String },  // To store the Stripe customer ID
// });
//
// // Create a model for User
// const User = mongoose.model('User', userSchema);
//
// module.exports = User;


const mongoose = require('mongoose');

const AddressSchema = new mongoose.Schema({
  street: {
    type: String,
    trim: true
  },
  city: {
    type: String,
    trim: true
  },
  state: {
    type: String,
    trim: true
  },
  zipCode: {
    type: String,
    trim: true
  },
  country: {
    type: String,
    trim: true,
    default: 'US'
  },
  isDefault: {
    type: Boolean,
    default: false
  }
}, { _id: true, timestamps: true });

const PaymentHistorySchema = new mongoose.Schema({
  paymentIntentId: {
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
  status: {
    type: String,
    enum: ['succeeded', 'processing', 'failed', 'canceled'],
    required: true
  },
  paymentMethodId: {
    type: String
  },
  paymentMethodLast4: {
    type: String
  },
  invoiceId: {
    type: String
  },
  invoiceNumber: {
    type: String
  },
  subscriptionId: {
    type: String
  },
  orderId: {
    type: String
  }
}, { timestamps: true });

const orderItemSchema = new mongoose.Schema({
  name: String,
  description: String,
  quantity: Number,
  price: Number,
  subtotal: Number,
  productId: String,
  metadata: Object
}, { _id: false });

const addressSchema = new mongoose.Schema({
  name: String,
  line1: String,
  line2: String,
  city: String,
  state: String,
  postalCode: String,
  country: String,
  phone: String
}, { _id: false });

const orderSchema = new mongoose.Schema({
  orderId: { type: String, required: true },
  paymentIntentId: { type: String, required: true },
  customerId: { type: String, required: true },
  totalAmount: { type: Number, required: true },
  currency: { type: String, required: true, default: 'usd' },
  items: [orderItemSchema],
  shippingAddress: addressSchema,
  billingAddress: addressSchema,
  status: { type: String, required: true },
  paymentStatus: { type: String, required: true },
  paymentMethodId: String,
  paymentMethodLast4: String,
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date }
});

const UserSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,  // This creates an index automatically
    trim: true,
    lowercase: true
  },
  password: {
    type: String,
    required: true
  },
  firstName: {
    type: String,
    trim: true
  },
  lastName: {
    type: String,
    trim: true
  },
  phoneNumber: {
    type: String,
    trim: true
  },
  customerId: {
    type: String,
    required: true
  },
  defaultPaymentMethodId: {
    type: String,
    default: null
  },
  paymentMethods: [{
    paymentMethodId: {
      type: String,
      required: true
    },
    brand: {
      type: String
    },
    last4: {
      type: String
    },
    expMonth: {
      type: Number
    },
    expYear: {
      type: Number
    },
    isDefault: {
      type: Boolean,
      default: false
    }
  }],
  addresses: [AddressSchema],
  paymentHistory: [PaymentHistorySchema],
  subscriptionId: {
    type: String,
    default: null
  },
  subscriptionStatus: {
    type: String,
    enum: ['active', 'trialing', 'past_due', 'canceled', 'incomplete', 'incomplete_expired', null],
    default: null
  },
  subscriptionPeriodEnd: {
    type: Date,
    default: null
  },
  subscriptionPriceId: {
    type: String,
    default: null
  },
  subscriptionProductId: {
    type: String,
    default: null
  },
  cancelAtPeriodEnd: {
    type: Boolean,
    default: false
  },
  subscriptionBillingDetails: {
    interval: String,
    intervalCount: Number,
    amount: Number,
    currency: String,
    productName: String,
    productId: String,
    trialEnd: Date
  },
  accountDeletionRequested: {
    type: Boolean,
    default: false
  },
  accountDeletionRequestedAt: {
    type: Date,
    default: null
  },
  role: {
    type: String,
    enum: ['user', 'admin'],
    default: 'user'
  },
  isEmailVerified: {
    type: Boolean,
    default: false
  },
  emailVerificationToken: {
    type: String
  },
  passwordResetToken: {
    type: String
  },
  passwordResetExpires: {
    type: Date
  },
  lastLogin: {
    type: Date
  },
  active: {
    type: Boolean,
    default: true
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  orders: [orderSchema],
  createdSubscriptionPlans: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'SubscriptionPlan'
  }]
}, { timestamps: true });

// Create a virtual for the full name
UserSchema.virtual('fullName').get(function() {
  if (this.firstName && this.lastName) {
    return `${this.firstName} ${this.lastName}`;
  }
  return this.email.split('@')[0];
});

// Add method to check if a payment method exists
UserSchema.methods.hasPaymentMethod = function(paymentMethodId) {
  return this.paymentMethods.some(method => method.paymentMethodId === paymentMethodId);
};

// Add a pre-save hook to ensure only one default address
UserSchema.pre('save', function(next) {
  if (this.isModified('addresses')) {
    // If a new default address is being set, unset any existing default
    const defaultAddressIndex = this.addresses.findIndex(addr => addr.isDefault);
    if (defaultAddressIndex >= 0) {
      this.addresses.forEach((addr, index) => {
        if (index !== defaultAddressIndex) {
          addr.isDefault = false;
        }
      });
    }
  }

  // Ensure only one default payment method
  if (this.isModified('paymentMethods')) {
    if (this.defaultPaymentMethodId) {
      this.paymentMethods.forEach(method => {
        method.isDefault = method.paymentMethodId === this.defaultPaymentMethodId;
      });
    }
  }

  next();
});

// Add only the indexes that aren't automatically created
UserSchema.index({ customerId: 1 });
UserSchema.index({ subscriptionStatus: 1 });

module.exports = mongoose.model('User', UserSchema);