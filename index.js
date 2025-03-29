const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const dotenv = require('dotenv');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const stripe = require('stripe');
const User = require('./models/User');
const SubscriptionPlan = require('./models/SubscriptionPlan');
const DeletedUserFeedback = require('./models/DeletedUserFeedback');

dotenv.config();

const app = express();
const stripeClient = stripe(process.env.STRIPE_SECRET_KEY);

// 1. Define the webhook route BEFORE anybody parsing middleware
app.post('/webhook', express.raw({type: 'application/json'}), async (req, res) => {
  console.log('Webhook received with correct body parser!');
  const sig = req.headers['stripe-signature'];
  
  if (!sig) {
    console.error('No Stripe signature found in webhook request');
    return res.status(400).send('No Stripe signature');
  }
  
  if (!process.env.STRIPE_WEBHOOK_SECRET) {
    console.error('STRIPE_WEBHOOK_SECRET is not defined in environment variables');
    return res.status(500).send('Webhook secret not configured');
  }
  
  let event;

  try {
    // Debug info
    console.log('Body type:', typeof req.body);
    console.log('Body is Buffer?', Buffer.isBuffer(req.body));
    
    // Verify the webhook signature using your webhook secret
    event = stripeClient.webhooks.constructEvent(
      req.body, // This is now the raw buffer!
      sig,
      process.env.STRIPE_WEBHOOK_SECRET
    );
    console.log(`Webhook verified! Event type: ${event.type}`);
    
     // Handle specific payment events
     switch (event.type) {
      case 'payment_intent.succeeded':
        console.log('Processing payment_intent.succeeded event');
        const paymentIntent = event.data.object;
        
        await handleSuccessfulPayment(paymentIntent);
        
        // Additionally update any associated order
        if (paymentIntent.metadata && paymentIntent.metadata.orderId) {
          console.log('Payment has associated order:', paymentIntent.metadata.orderId);
          console.log('Payment metadata:', paymentIntent.metadata);
          
          // Get userId from the metadata or try to find the user by customerId
          let userId = paymentIntent.metadata.userId;
          
          if (!userId && paymentIntent.customer) {
            // Try to find the user by customerId
            const user = await User.findOne({ customerId: paymentIntent.customer });
            if (user) {
              userId = user._id.toString();
              console.log(`Found user ${userId} by customerId ${paymentIntent.customer}`);
            }
          }
          
          if (userId) {
            await updateOrderStatus(
              userId,
              paymentIntent.metadata.orderId, 
              'completed', 
              'succeeded'
            );
          } else {
            console.error(`No userId found for order ${paymentIntent.metadata.orderId}`);
          }
        }
        break;
      
      case 'payment_intent.payment_failed':
        console.log('Processing payment_intent.payment_failed event');
        await handleFailedPayment(event.data.object);
        
        // Additionally update any associated order
        if (event.data.object.metadata && event.data.object.metadata.orderId) {
          await updateOrderStatus(
            event.data.object.metadata.userId,
            event.data.object.metadata.orderId, 
            'failed', 
            'failed'
          );
        }
        break;
      
      case 'payment_intent.requires_action':
        console.log('Processing payment_intent.requires_action event');
        await handlePaymentRequiresAction(event.data.object);
        break;
      
      case 'payment_intent.canceled':
        console.log('Processing payment_intent.canceled event');
        await handleCanceledPayment(event.data.object);
        break;
      
      case 'payment_intent.created':
        console.log('Payment intent created, no action needed');
        break;
      
      case 'charge.succeeded':
        console.log('Charge succeeded, no additional action needed');
        break;
      
      case 'charge.updated':
        console.log('Charge updated, no additional action needed');
        break;
      
      case 'charge.failed':
        console.log('Processing charge.failed event');
        // You could handle failed charges separately if needed
        break;
      
      case 'customer.subscription.created':
        console.log('Processing customer.subscription.created event');
        await handleSubscriptionCreated(event.data.object);
        break;
      
      case 'customer.subscription.updated':
        console.log('Processing customer.subscription.updated event');
        await handleSubscriptionUpdated(event.data.object);
        break;
      
      case 'customer.subscription.deleted':
        console.log('Processing customer.subscription.deleted event');
        await handleSubscriptionCanceled(event.data.object);
        break;
      
      case 'invoice.payment_succeeded':
        console.log('Processing invoice.payment_succeeded event');
        await handleInvoicePaid(event.data.object);
        break;
      
      case 'invoice.payment_failed':
        console.log('Processing invoice.payment_failed event');
        await handleInvoicePaymentFailed(event.data.object);
        break;
      
      default:
        console.log(`Unhandled event type: ${event.type}`);
    }

    // Return a 200 response to acknowledge receipt of the event
    console.log('Webhook processed successfully');
    return res.status(200).json({ received: true });
  } catch (err) {
    console.error(`Webhook signature verification failed: ${err.message}`);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }
});


// 2. AFTER the webhook route, add the JSON parser for all other routes
app.use(express.json());

mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('MongoDB connected'))
    .catch((err) => console.error('MongoDB connection error:', err));

// Authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'Unauthorized: No token provided' });
  }

  const token = authHeader.split(' ')[1];
  jwt.verify(token, process.env.JWT_SECRET_KEY, (err, user) => {
    if (err) return res.status(403).json({ message: 'Forbidden: Invalid token' });
    req.user = user;
    next();
  });
};

// Register API with Stripe customer ID
app.post('/register', async (req, res) => {
  const { email, password } = req.body;
  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ message: 'User already exists' });

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const customer = await stripeClient.customers.create({ email });

    const newUser = new User({
      email,
      password: hashedPassword,
      customerId: customer.id,
    });

    await newUser.save();

    res.status(201).json({
      message: 'User registered successfully',
      user: { email: newUser.email, customerId: newUser.customerId },
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Login API with JWT access token
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: 'Invalid credentials' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });

    const token = jwt.sign(
        { userId: user._id, email: user.email, customerId: user.customerId },
        process.env.JWT_SECRET_KEY,
        { expiresIn: '12h' }
    );

    res.status(200).json({
      message: 'Login successful',
      token,
      user: { email: user.email, customerId: user.customerId },
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Payment intent API with Stripe client_secret

// app.post('/create-payment-intent', authenticateToken, async (req, res) => {
//   const { amount, currency } = req.body;
//   try {
//     if (!amount || !currency) {
//       return res.status(400).json({ message: 'Missing required fields' });
//     }

//     const paymentIntent = await stripeClient.paymentIntents.create({
//       amount,
//       currency,
//       customer: req.user.customerId,
//     });

//     res.status(200).json({
//       clientSecret: paymentIntent.client_secret,
//       message: 'Payment intent created successfully',
//     });
//   } catch (error) {
//     console.error(error);
//     res.status(500).json({ message: 'Error creating payment intent' });
//   }
// });

// Payment intent API with Stripe client_secret and optional confirmation
app.post('/create-payment-intent', authenticateToken, async (req, res) => {
  const { amount, currency, confirm = false } = req.body;
  try {
    if (!amount || !currency) {
      return res.status(400).json({ message: 'Missing required fields' });
    }

    // Create the payment intent
    const paymentIntentParams = {
      amount,
      currency,
      customer: req.user.customerId,
      // Disable redirect-based payment methods
      automatic_payment_methods: {
        enabled: false
      },
      // Only allow card payments (which don't require redirects)
      payment_method_types: ['card']
    };
    
    // If confirm is true, add confirmation details
    if (confirm) {
      paymentIntentParams.payment_method = 'pm_card_visa';
      paymentIntentParams.confirm = true;
    }

    const paymentIntent = await stripeClient.paymentIntents.create(paymentIntentParams);

    // Response includes different details based on whether payment was confirmed
    const response = {
      message: confirm ? 'Payment intent created and confirmed' : 'Payment intent created successfully',
      clientSecret: paymentIntent.client_secret,
      paymentIntentId: paymentIntent.id
    };
    
    if (confirm) {
      response.status = paymentIntent.status;
      
      // If payment was confirmed, record in payment history
      if (paymentIntent.status === 'succeeded') {
        await User.findByIdAndUpdate(
          req.user.userId,
          {
            $push: {
              paymentHistory: {
                paymentIntentId: paymentIntent.id,
                amount: paymentIntent.amount,
                currency: paymentIntent.currency,
                status: paymentIntent.status,
                paymentMethodId: paymentIntent.payment_method,
                paymentMethodLast4: 'visa-test'
              }
            }
          }
        );
      }
    }

    res.status(200).json(response);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error creating payment intent', error: error.message });
  }
});

// Process payment directly with card with Stripe
app.post('/process-payment', authenticateToken, async (req, res) => {
  const { amount, currency } = req.body;

  if (!amount || !currency) {
    return res.status(400).json({ message: 'Missing required fields' });
  }

  try {
    // Use Stripe's test token instead of raw card data
    const paymentMethod = await stripeClient.paymentMethods.create({
      type: 'card',
      card: {
        token: 'tok_visa', // Test Visa card token
      },
    });

    const paymentIntent = await stripeClient.paymentIntents.create({
      amount,
      currency,
      payment_method: paymentMethod.id,
      customer: req.user.customerId,
      confirm: true,
      // Disable redirect-based payment methods entirely
      automatic_payment_methods: {
        enabled: false
      },
      // Only allow card payments (which don't require redirects in most cases)
      payment_method_types: ['card']
    });

    // Record payment history in the user's document
    await User.findByIdAndUpdate(
      req.user.userId,
      {
        $push: {
          paymentHistory: {
            paymentIntentId: paymentIntent.id,
            amount: paymentIntent.amount,
            currency: paymentIntent.currency,
            status: paymentIntent.status,
            paymentMethodId: paymentMethod.id,
            paymentMethodLast4: paymentMethod.card.last4
          }
        }
      }
    );

    return res.status(200).json({
      message: 'Payment successful',
      paymentIntent: {
        id: paymentIntent.id,
        status: paymentIntent.status,
        amount: paymentIntent.amount,
        currency: paymentIntent.currency
      }
    });
  } catch (error) {
    console.error('Stripe Error:', error);
    return res.status(500).json({ message: 'Error processing payment', error: error.message });
  }
});

// Saved card list API with Stripe
app.get('/cards', authenticateToken, async (req, res) => {
  try {
    const paymentMethods = await stripeClient.paymentMethods.list({
      customer: req.user.customerId,
      type: 'card',
    });

    // Get user to determine default payment method
    const user = await User.findById(req.user.userId);
    const defaultPaymentMethodId = user.defaultPaymentMethodId || null;

    const cards = paymentMethods.data.map(pm => {
      const card = pm.card;
      return {
        id: pm.id,
        brand: card.brand,
        last4: card.last4,
        expMonth: card.exp_month,
        expYear: card.exp_year,
        isDefault: pm.id === defaultPaymentMethodId
      };
    });

    res.status(200).json({ cards });
  } catch (error) {
    console.error('Error fetching cards:', error);
    res.status(500).json({ message: 'Error fetching saved cards', error: error.message });
  }
});

// Add new card API with Stripe
app.post('/cards', authenticateToken, async (req, res) => {
  const { cardNumber, expMonth, expYear, cvc } = req.body;
  
  if (!cardNumber || !expMonth || !expYear || !cvc) {
    return res.status(400).json({ message: 'Missing required card fields' });
  }

  try {
    let paymentMethod;
    let cardSource = 'unknown';
    let detectedType = 'unknown';
    
    // Check if this is a test card number we can map to a token
    if (cardNumber === '4242424242424242' || 
        cardNumber === '4000056655665556' || 
        cardNumber.startsWith('42')) {
      // Visa test card
      paymentMethod = await stripeClient.paymentMethods.create({
        type: 'card',
        card: { token: 'tok_visa' }
      });
      cardSource = 'test_token';
      detectedType = 'visa';
    } else if (cardNumber === '5555555555554444' || 
               cardNumber.startsWith('55')) {
      // Mastercard test card
      paymentMethod = await stripeClient.paymentMethods.create({
        type: 'card',
        card: { token: 'tok_mastercard' }
      });
      cardSource = 'test_token';
      detectedType = 'mastercard';
    } else if (cardNumber === '378282246310005' || 
               cardNumber === '371449635398431' || 
               cardNumber.startsWith('34') || 
               cardNumber.startsWith('37')) {
      // American Express test card
      paymentMethod = await stripeClient.paymentMethods.create({
        type: 'card',
        card: { token: 'tok_amex' }
      });
      cardSource = 'test_token';
      detectedType = 'amex';
    } else if (cardNumber === '6011111111111117' || 
               cardNumber.startsWith('6011')) {
      // Discover test card
      paymentMethod = await stripeClient.paymentMethods.create({
        type: 'card',
        card: { token: 'tok_discover' }
      });
      cardSource = 'test_token';
      detectedType = 'discover';
    } else {
      // For any other card, try to process as a real card
      try {
        console.log("Attempting to process raw card data...");
        paymentMethod = await stripeClient.paymentMethods.create({
          type: 'card',
          card: {
            number: cardNumber,
            exp_month: expMonth,
            exp_year: expYear,
            cvc: cvc,
          },
        });
        cardSource = 'raw_card_api';
        detectedType = 'real_card';
      } catch (cardError) {
        console.log("Raw card processing failed, fallback to token:", cardError.message);
        // If raw card API access is not enabled, fallback to a test card based on
        // the first digit of the card number (rough card type detection)
        const firstDigit = cardNumber.charAt(0);
        
        if (firstDigit === '4') {
          // Visa-like
          paymentMethod = await stripeClient.paymentMethods.create({
            type: 'card',
            card: { token: 'tok_visa' }
          });
          cardSource = 'fallback_token';
          detectedType = 'visa_fallback';
        } else if (firstDigit === '5') {
          // Mastercard-like
          paymentMethod = await stripeClient.paymentMethods.create({
            type: 'card',
            card: { token: 'tok_mastercard' }
          });
          cardSource = 'fallback_token';
          detectedType = 'mastercard_fallback';
        } else if (firstDigit === '3') {
          // Amex-like or Diners-like
          paymentMethod = await stripeClient.paymentMethods.create({
            type: 'card',
            card: { token: 'tok_amex' }
          });
          cardSource = 'fallback_token';
          detectedType = 'amex_fallback';
        } else if (firstDigit === '6') {
          // Discover-like
          paymentMethod = await stripeClient.paymentMethods.create({
            type: 'card',
            card: { token: 'tok_discover' }
          });
          cardSource = 'fallback_token';
          detectedType = 'discover_fallback';
        } else {
          // Default to Visa if no match
          paymentMethod = await stripeClient.paymentMethods.create({
            type: 'card',
            card: { token: 'tok_visa' }
          });
          cardSource = 'default_token';
          detectedType = 'default_visa';
        }
      }
    }

    // Attach the payment method to the customer
    await stripeClient.paymentMethods.attach(paymentMethod.id, {
      customer: req.user.customerId,
    });

    // If this is the first card, set it as default
    const paymentMethods = await stripeClient.paymentMethods.list({
      customer: req.user.customerId,
      type: 'card',
    });

    if (paymentMethods.data.length === 1) {
      // Update the customer's default payment method
      await stripeClient.customers.update(req.user.customerId, {
        invoice_settings: {
          default_payment_method: paymentMethod.id,
        },
      });

      // Save the default payment method ID to the user
      await User.findByIdAndUpdate(req.user.userId, {
        defaultPaymentMethodId: paymentMethod.id
      });
    }

    res.status(201).json({
      message: 'Card added successfully',
      card: {
        id: paymentMethod.id,
        brand: paymentMethod.card.brand,
        last4: paymentMethod.card.last4,
        expMonth: paymentMethod.card.exp_month,
        expYear: paymentMethod.card.exp_year,
        isDefault: paymentMethods.data.length === 1
      },
      debug: {
        inputCardNumber: cardNumber.slice(0, 6) + '******' + cardNumber.slice(-4),
        cardSource,
        detectedType,
        firstDigit: cardNumber.charAt(0)
      }
    });
  } catch (error) {
    console.error('Error adding card:', error);
    res.status(500).json({ message: 'Error adding card', error: error.message });
  }
});

// Set primary card API with Stripe
app.post('/cards/:cardId/set-default', authenticateToken, async (req, res) => {
  const { cardId } = req.params;

  try {
    // Verify this payment method belongs to the customer
    const paymentMethod = await stripeClient.paymentMethods.retrieve(cardId);
    if (paymentMethod.customer !== req.user.customerId) {
      return res.status(403).json({ message: 'This card does not belong to your account' });
    }

    // Update the customer's default payment method
    await stripeClient.customers.update(req.user.customerId, {
      invoice_settings: {
        default_payment_method: cardId,
      },
    });

    // Save the default payment method ID to the user
    await User.findByIdAndUpdate(req.user.userId, {
      defaultPaymentMethodId: cardId
    });

    res.status(200).json({ message: 'Default payment method updated successfully' });
  } catch (error) {
    console.error('Error setting default card:', error);
    res.status(500).json({ message: 'Error setting default payment method', error: error.message });
  }
});

// Update existing card API with Stripe
app.put('/cards/:cardId', authenticateToken, async (req, res) => {
  const { cardId } = req.params;
  const { expMonth, expYear } = req.body;

  if (!expMonth || !expYear) {
    return res.status(400).json({ message: 'Missing required fields' });
  }

  try {
    // Verify this payment method belongs to the customer
    const paymentMethod = await stripeClient.paymentMethods.retrieve(cardId);
    if (paymentMethod.customer !== req.user.customerId) {
      return res.status(403).json({ message: 'This card does not belong to your account' });
    }

    // Update the payment method
    const updatedPaymentMethod = await stripeClient.paymentMethods.update(cardId, {
      card: {
        exp_month: expMonth,
        exp_year: expYear,
      },
    });

    res.status(200).json({
      message: 'Card updated successfully',
      card: {
        id: updatedPaymentMethod.id,
        brand: updatedPaymentMethod.card.brand,
        last4: updatedPaymentMethod.card.last4,
        expMonth: updatedPaymentMethod.card.exp_month,
        expYear: updatedPaymentMethod.card.exp_year,
        cvc: updatedPaymentMethod.card.cvc,
      }
    });
  } catch (error) {
    console.error('Error updating card:', error);
    res.status(500).json({ message: 'Error updating card', error: error.message });
  }
});

// Delete card API with Stripe
app.delete('/cards/:cardId', authenticateToken, async (req, res) => {
  const { cardId } = req.params;

  try {
    // Verify this payment method belongs to the customer
    const paymentMethod = await stripeClient.paymentMethods.retrieve(cardId);
    if (paymentMethod.customer !== req.user.customerId) {
      return res.status(403).json({ message: 'This card does not belong to your account' });
    }

    // Get user to check if this is the default payment method
    const user = await User.findById(req.user.userId);

    // If deleting the default payment method, set another one as default if available
    if (user.defaultPaymentMethodId === cardId) {
      const paymentMethods = await stripeClient.paymentMethods.list({
        customer: req.user.customerId,
        type: 'card',
      });

      // Filter out the one being deleted
      const otherCards = paymentMethods.data.filter(pm => pm.id !== cardId);

      if (otherCards.length > 0) {
        // Set the first available card as the new default
        await stripeClient.customers.update(req.user.customerId, {
          invoice_settings: {
            default_payment_method: otherCards[0].id,
          },
        });

        // Update user record
        user.defaultPaymentMethodId = otherCards[0].id;
        await user.save();
      } else {
        // No other cards, remove default
        user.defaultPaymentMethodId = null;
        await user.save();
      }
    }

    // Detach the payment method from the customer
    await stripeClient.paymentMethods.detach(cardId);

    res.status(200).json({ message: 'Card deleted successfully' });
  } catch (error) {
    console.error('Error deleting card:', error);
    res.status(500).json({ message: 'Error deleting card', error: error.message });
  }
});

// Process payment directly with saved card with Stripe
app.post('/process-payment-with-saved-card', authenticateToken, async (req, res) => {
  const { amount, currency, paymentMethodId } = req.body;

  if (!amount || !currency) {
    return res.status(400).json({ message: 'Amount and currency are required' });
  }

  try {
    // Get the user to find their default payment method if none provided
    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Use provided payment method ID or fall back to user's default
    let selectedPaymentMethodId = paymentMethodId || user.defaultPaymentMethodId;
    
    // If still no payment method, return an error
    if (!selectedPaymentMethodId) {
      return res.status(400).json({ 
        message: 'No payment method provided and no default payment method set',
        canAddCard: true
      });
    }

    // Verify this payment method belongs to the customer
    const paymentMethod = await stripeClient.paymentMethods.retrieve(selectedPaymentMethodId);
    if (paymentMethod.customer !== req.user.customerId) {
      return res.status(403).json({ message: 'This payment method does not belong to your account' });
    }

    const paymentIntent = await stripeClient.paymentIntents.create({
      amount,
      currency,
      customer: req.user.customerId,
      payment_method: selectedPaymentMethodId,
      confirm: true,
      // Disable redirect-based payment methods
      automatic_payment_methods: {
        enabled: false
      },
      // Only allow card payments
      payment_method_types: ['card']
    });

    // Record payment history in the user's document
    await User.findByIdAndUpdate(
      req.user.userId,
      {
        $push: {
          paymentHistory: {
            paymentIntentId: paymentIntent.id,
            amount: paymentIntent.amount,
            currency: paymentIntent.currency,
            status: paymentIntent.status,
            paymentMethodId: selectedPaymentMethodId,
            paymentMethodLast4: paymentMethod.card.last4
          }
        }
      }
    );

    res.status(200).json({
      message: 'Payment successful',
      paymentIntent: {
        id: paymentIntent.id,
        status: paymentIntent.status,
        amount: paymentIntent.amount,
        currency: paymentIntent.currency
      },
      paymentMethod: {
        id: paymentMethod.id,
        brand: paymentMethod.card.brand,
        last4: paymentMethod.card.last4,
        isDefault: selectedPaymentMethodId === user.defaultPaymentMethodId
      }
    });
  } catch (error) {
    console.error('Stripe Error:', error);
    res.status(500).json({ message: 'Error processing payment', error: error.message });
  }
});

// Verify payment API with Stripe
app.get('/verify-payment/:paymentIntentId', authenticateToken, async (req, res) => {
  const { paymentIntentId } = req.params;

  try {
    const paymentIntent = await stripeClient.paymentIntents.retrieve(paymentIntentId);

    // Verify this payment belongs to the customer
    if (paymentIntent.customer !== req.user.customerId) {
      return res.status(403).json({ message: 'This payment does not belong to your account' });
    }

    res.status(200).json({
      verified: paymentIntent.status === 'succeeded',
      status: paymentIntent.status,
      amount: paymentIntent.amount,
      currency: paymentIntent.currency,
      paymentMethod: paymentIntent.payment_method,
      created: new Date(paymentIntent.created * 1000).toISOString(),
    });
  } catch (error) {
    console.error('Error verifying payment:', error);
    res.status(500).json({ message: 'Error verifying payment', error: error.message });
  }
});

// Get payment history API
app.get('/payment-history', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const paymentHistory = user.paymentHistory || [];
    
    // Sort by most recent first
    paymentHistory.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

    res.status(200).json({
      paymentHistory: paymentHistory.map(payment => ({
        id: payment._id,
        paymentIntentId: payment.paymentIntentId,
        amount: payment.amount,
        currency: payment.currency,
        status: payment.status,
        paymentMethodLast4: payment.paymentMethodLast4,
        date: payment.createdAt
      }))
    });
  } catch (error) {
    console.error('Error fetching payment history:', error);
    res.status(500).json({ message: 'Error fetching payment history', error: error.message });
  }
});

// Get specific payment details API
app.get('/payment-history/:paymentId', authenticateToken, async (req, res) => {
  const { paymentId } = req.params;
  
  try {
    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Find the specific payment in the user's payment history
    const payment = user.paymentHistory.id(paymentId);
    if (!payment) {
      return res.status(404).json({ message: 'Payment not found' });
    }

    // Get additional details from Stripe if needed
    const paymentIntent = await stripeClient.paymentIntents.retrieve(payment.paymentIntentId);

    res.status(200).json({
      payment: {
        id: payment._id,
        paymentIntentId: payment.paymentIntentId,
        amount: payment.amount,
        currency: payment.currency,
        status: payment.status,
        paymentMethodId: payment.paymentMethodId,
        paymentMethodLast4: payment.paymentMethodLast4,
        date: payment.createdAt,
        stripeDetails: {
          receiptUrl: paymentIntent.charges?.data[0]?.receipt_url || null,
          paymentMethod: paymentIntent.payment_method_types,
          description: paymentIntent.description || null
        }
      }
    });
  } catch (error) {
    console.error('Error fetching payment details:', error);
    res.status(500).json({ message: 'Error fetching payment details', error: error.message });
  }
});

// Helper function to handle successful payments
async function handleSuccessfulPayment(paymentIntent) {
  console.log(`PaymentIntent ${paymentIntent.id} was successful!`);
  
  try {
    // Find the user by customer ID
    const user = await User.findOne({ customerId: paymentIntent.customer });
    
    if (!user) {
      console.error(`No user found for customer ID: ${paymentIntent.customer}`);
      return;
    }
    
    // Check if this payment is already recorded
    const existingPayment = await User.findOne({
      _id: user._id,
      'paymentHistory.paymentIntentId': paymentIntent.id
    });
    
    if (existingPayment) {
      console.log(`Payment ${paymentIntent.id} already recorded for user ${user.email}`);
      return;
    }

    // Get payment method details to record last4
    let paymentMethodLast4 = 'unknown';
    if (paymentIntent.payment_method) {
      try {
        const paymentMethod = await stripeClient.paymentMethods.retrieve(paymentIntent.payment_method);
        paymentMethodLast4 = paymentMethod.card?.last4 || 'unknown';
      } catch (err) {
        console.error(`Error retrieving payment method: ${err.message}`);
      }
    }
    
    // Record the payment
    await User.findByIdAndUpdate(
      user._id,
      {
        $push: {
          paymentHistory: {
            paymentIntentId: paymentIntent.id,
            amount: paymentIntent.amount,
            currency: paymentIntent.currency,
            status: paymentIntent.status,
            paymentMethodId: paymentIntent.payment_method,
            paymentMethodLast4: paymentMethodLast4
          }
        }
      }
    );
    
    console.log(`Payment ${paymentIntent.id} recorded for user ${user.email}`);
  } catch (err) {
    console.error(`Error recording successful payment: ${err.message}`);
    throw err;
  }
}

// Helper function to handle failed payments
async function handleFailedPayment(paymentIntent) {
  console.log(`Payment failed for PaymentIntent ${paymentIntent.id}`);
  const errorMessage = paymentIntent.last_payment_error 
    ? paymentIntent.last_payment_error.message 
    : 'Unknown error';
  
  try {
    // Find the user by customer ID
    const user = await User.findOne({ customerId: paymentIntent.customer });
    
    if (!user) {
      console.error(`No user found for customer ID: ${paymentIntent.customer}`);
      return;
    }
    
    // Record the failed payment
    await User.findByIdAndUpdate(
      user._id,
      {
        $push: {
          paymentHistory: {
            paymentIntentId: paymentIntent.id,
            amount: paymentIntent.amount,
            currency: paymentIntent.currency,
            status: 'failed',
            errorMessage: errorMessage,
            paymentMethodId: paymentIntent.payment_method
          }
        }
      }
    );
    
    console.log(`Failed payment ${paymentIntent.id} recorded for user ${user.email}`);
  } catch (err) {
    console.error(`Error recording failed payment: ${err.message}`);
    throw err;
  }
}

// Helper function to handle payments requiring additional action
async function handlePaymentRequiresAction(paymentIntent) {
  console.log(`PaymentIntent ${paymentIntent.id} requires action: ${paymentIntent.next_action?.type}`);
  // You might want to notify the user that they need to complete the payment
  // This could be through push notifications, emails, or other channels
}

// Helper function to handle canceled payments
async function handleCanceledPayment(paymentIntent) {
  console.log(`PaymentIntent ${paymentIntent.id} was canceled`);
  
  try {
    // Find the user by customer ID
    const user = await User.findOne({ customerId: paymentIntent.customer });
    
    if (!user) {
      console.error(`No user found for customer ID: ${paymentIntent.customer}`);
      return;
    }
    
    // Record the canceled payment
    await User.findByIdAndUpdate(
      user._id,
      {
        $push: {
          paymentHistory: {
            paymentIntentId: paymentIntent.id,
            amount: paymentIntent.amount,
            currency: paymentIntent.currency,
            status: 'canceled',
            paymentMethodId: paymentIntent.payment_method
          }
        }
      }
    );
    
    console.log(`Canceled payment ${paymentIntent.id} recorded for user ${user.email}`);
  } catch (err) {
    console.error(`Error recording canceled payment: ${err.message}`);
    throw err;
  }
}

// Test endpoint to confirm payments (for testing only - not for production use)
app.post('/confirm-test-payment', authenticateToken, async (req, res) => {
  const { paymentIntentId } = req.body;
  
  if (!paymentIntentId) {
    return res.status(400).json({ message: 'Payment Intent ID is required' });
  }
  
  try {
    // Confirm the payment intent with a test card
    const paymentIntent = await stripeClient.paymentIntents.confirm(
      paymentIntentId,
      {
        payment_method: 'pm_card_visa' // This is a Stripe test card
      }
    );
    
    res.status(200).json({
      message: 'Payment confirmed for testing',
      paymentIntent: {
        id: paymentIntent.id,
        status: paymentIntent.status,
        amount: paymentIntent.amount,
        currency: paymentIntent.currency
      }
    });
  } catch (error) {
    console.error('Error confirming test payment:', error);
    res.status(500).json({ message: 'Error confirming payment', error: error.message });
  }
});

// Cart Order Checkout API
app.post('/checkout', authenticateToken, async (req, res) => {
  const { 
    items, 
    paymentMethodId, 
    shippingAddress,
    billingAddress,
    currency = 'usd'
  } = req.body;
  
  // Validate request body
  if (!items || !Array.isArray(items) || items.length === 0) {
    return res.status(400).json({ message: 'Cart items are required' });
  }

  try {
    // Get the user to find their default payment method if none provided
    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Calculate the total amount from cart items
    let totalAmount = 0;
    const lineItems = [];
    
    items.forEach(item => {
      if (!item.price || !item.quantity || item.quantity <= 0) {
        throw new Error('Invalid item data: each item must have a price and positive quantity');
      }
      
      // Convert price to cents (Stripe uses smallest currency unit)
      const itemPrice = Math.round(parseFloat(item.price) * 100);
      const itemTotal = itemPrice * item.quantity;
      totalAmount += itemTotal;
      
      lineItems.push({
        name: item.name || 'Product',
        description: item.description || '',
        quantity: item.quantity,
        price: itemPrice,
        subtotal: itemTotal,
        productId: item.productId || '',
        metadata: item.metadata || {}
      });
    });
    
    if (totalAmount <= 0) {
      return res.status(400).json({ message: 'Total amount must be greater than 0' });
    }

    // Use provided payment method ID or fall back to user's default
    let selectedPaymentMethodId = paymentMethodId || user.defaultPaymentMethodId;
    
    // If still no payment method, return an error
    if (!selectedPaymentMethodId) {
      return res.status(400).json({ 
        message: 'No payment method provided and no default payment method set',
        canAddCard: true
      });
    }

    // Verify this payment method belongs to the customer
    const paymentMethod = await stripeClient.paymentMethods.retrieve(selectedPaymentMethodId);
    if (paymentMethod.customer !== req.user.customerId) {
      return res.status(403).json({ message: 'This payment method does not belong to your account' });
    }

    // Create a unique order reference
    const orderReference = `order_${Date.now()}_${Math.random().toString(36).substring(2, 10)}`;
    
    // Create metadata for the payment
    const metadata = {
      orderId: orderReference,
      customerId: user.customerId,
      userId: user._id.toString(),
      itemCount: items.length,
      shipping: shippingAddress ? 'yes' : 'no'
    };

    // Create the payment intent
    const paymentIntent = await stripeClient.paymentIntents.create({
      amount: totalAmount,
      currency,
      customer: req.user.customerId,
      payment_method: selectedPaymentMethodId,
      confirm: true,
      description: `Order ${orderReference}`,
      metadata,
      // Disable redirect-based payment methods
      automatic_payment_methods: {
        enabled: false
      },
      // Only allow card payments
      payment_method_types: ['card'],
      receipt_email: user.email
    });

    // Create the order object to save
    const order = {
      orderId: orderReference,
      paymentIntentId: paymentIntent.id,
      customerId: user.customerId,
      totalAmount: totalAmount,
      currency,
      items: lineItems,
      shippingAddress: shippingAddress || null,
      billingAddress: billingAddress || shippingAddress || null,
      status: paymentIntent.status,
      paymentStatus: paymentIntent.status,
      paymentMethodId: selectedPaymentMethodId,
      paymentMethodLast4: paymentMethod.card.last4,
      createdAt: new Date(),
      updatedAt: new Date()
    };
    
    // Save the order using findOneAndUpdate for better atomicity
    const updatedUser = await User.findOneAndUpdate(
      { _id: req.user.userId },
      { $push: { orders: order } },
      { new: true }
    );

    // Verify the order was saved
    if (updatedUser && updatedUser.orders.some(o => o.orderId === orderReference)) {
      console.log(`✅ Order ${orderReference} successfully saved. User now has ${updatedUser.orders.length} orders.`);
    } else {
      console.error(`❌ Failed to save order ${orderReference}!`);
    }

    // Get receipt URL from the charge
    let receiptUrl = null;
    if (paymentIntent.status === 'succeeded' && paymentIntent.charges && paymentIntent.charges.data.length > 0) {
      receiptUrl = paymentIntent.charges.data[0].receipt_url;
    }

    // Respond with the order confirmation
    res.status(200).json({
      message: 'Order placed successfully',
      order: {
        orderId: orderReference,
        paymentIntentId: paymentIntent.id,
        status: paymentIntent.status,
        totalAmount: totalAmount,
        currency: currency,
        items: lineItems.map(item => ({
          name: item.name,
          quantity: item.quantity,
          price: item.price / 100, // Convert back to decimal for client
          subtotal: item.subtotal / 100 // Convert back to decimal for client
        })),
        paymentMethod: {
          id: paymentMethod.id,
          brand: paymentMethod.card.brand,
          last4: paymentMethod.card.last4
        },
        receiptUrl: receiptUrl,
        createdAt: new Date()
      }
    });
  } catch (error) {
    console.error('Checkout Error:', error);
    res.status(500).json({ 
      message: 'Error processing checkout', 
      error: error.message,
      code: error.code || 'unknown_error'
    });
  }
});

// Get user orders API
app.get('/orders', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const orders = user.orders || [];
    
    // Sort by most recent first
    orders.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

    res.status(200).json({
      orders: orders.map(order => ({
        orderId: order.orderId,
        paymentIntentId: order.paymentIntentId,
        totalAmount: order.totalAmount,
        currency: order.currency,
        status: order.status,
        itemCount: order.items.length,
        createdAt: order.createdAt
      }))
    });
  } catch (error) {
    console.error('Error fetching orders:', error);
    res.status(500).json({ message: 'Error fetching orders', error: error.message });
  }
});

// Get specific order details API
app.get('/orders/:orderId', authenticateToken, async (req, res) => {
  const { orderId } = req.params;
  
  try {
    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Find the specific order
    const order = user.orders?.find(o => o.orderId === orderId);
    if (!order) {
      return res.status(404).json({ message: 'Order not found' });
    }

    // Get additional details from Stripe if needed
    const paymentIntent = await stripeClient.paymentIntents.retrieve(order.paymentIntentId);
    
    // Get receipt URL from the charge
    let receiptUrl = null;
    if (paymentIntent.charges && paymentIntent.charges.data.length > 0) {
      receiptUrl = paymentIntent.charges.data[0].receipt_url;
    }

    res.status(200).json({
      order: {
        orderId: order.orderId,
        paymentIntentId: order.paymentIntentId,
        totalAmount: order.totalAmount,
        currency: order.currency,
        items: order.items.map(item => ({
          name: item.name,
          description: item.description,
          quantity: item.quantity,
          price: item.price / 100, // Convert back to decimal for client
          subtotal: item.subtotal / 100 // Convert back to decimal for client
        })),
        shippingAddress: order.shippingAddress,
        billingAddress: order.billingAddress,
        status: order.status,
        paymentStatus: paymentIntent.status,
        paymentMethod: {
          id: order.paymentMethodId,
          last4: order.paymentMethodLast4
        },
        receiptUrl: receiptUrl,
        createdAt: order.createdAt,
        updatedAt: paymentIntent.created > order.createdAt.getTime()/1000 
          ? new Date(paymentIntent.created * 1000) 
          : order.createdAt
      }
    });
  } catch (error) {
    console.error('Error fetching order details:', error);
    res.status(500).json({ message: 'Error fetching order details', error: error.message });
  }
});

// Improved order status update function
async function updateOrderStatus(userId, orderId, orderStatus, paymentStatus) {
  try {
    console.log(`Attempting to update order ${orderId} for user ${userId}`);
    
    // Find the user first
    const user = await User.findById(userId);
    
    if (!user) {
      console.error(`User ${userId} not found`);
      return;
    }
    
    // Check if the order exists
    const orderExists = user.orders.some(o => o.orderId === orderId);
    
    if (!orderExists) {
      console.error(`Order ${orderId} not found for user ${userId}`);
      console.log(`User has ${user.orders.length} orders. Order IDs:`, 
        user.orders.map(o => o.orderId));
      return;
    }
    
    // Update the order using dot notation for position-based updates
    const orderIndex = user.orders.findIndex(o => o.orderId === orderId);
    
    if (orderIndex === -1) {
      console.error(`Order ${orderId} not found in array despite existence check`);
      return;
    }
    
    // Set update fields
    const updateData = {};
    updateData[`orders.${orderIndex}.status`] = orderStatus;
    updateData[`orders.${orderIndex}.paymentStatus`] = paymentStatus;
    updateData[`orders.${orderIndex}.updatedAt`] = new Date();
    
    // Perform the update
    const updateResult = await User.findByIdAndUpdate(
      userId,
      { $set: updateData },
      { new: true }
    );
    
    console.log(`Updated order ${orderId} status to ${orderStatus}, result:`, 
      updateResult ? "Success" : "Failed");
  } catch (err) {
    console.error(`Error updating order status: ${err.message}`);
    console.error(err.stack);
  }
}

// Create Subscription API
app.post('/subscriptions', authenticateToken, async (req, res) => {
  const { 
    priceId,  // Stripe Price ID
    paymentMethodId, // Optional - use default if not provided
    couponId, // Optional coupon code
    trialDays // Optional trial period
  } = req.body;
  
  if (!priceId) {
    return res.status(400).json({ message: 'Price ID is required' });
  }
  
  try {
    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    // Check if user already has an active subscription
    if (user.subscriptionId && user.subscriptionStatus === 'active') {
      return res.status(400).json({ 
        message: 'User already has an active subscription',
        subscriptionId: user.subscriptionId,
        status: user.subscriptionStatus
      });
    }
    
    // Use provided payment method or default payment method
    let selectedPaymentMethodId = paymentMethodId || user.defaultPaymentMethodId;
    
    if (!selectedPaymentMethodId) {
      return res.status(400).json({ 
        message: 'No payment method provided and no default payment method set',
        canAddCard: true
      });
    }
    
    // Verify payment method belongs to customer
    const paymentMethod = await stripeClient.paymentMethods.retrieve(selectedPaymentMethodId);
    if (paymentMethod.customer !== user.customerId) {
      return res.status(403).json({ message: 'This payment method does not belong to your account' });
    }
    
    // Build subscription parameters
    const subscriptionParams = {
      customer: user.customerId,
      items: [{ price: priceId }],
      default_payment_method: selectedPaymentMethodId,
      expand: ['latest_invoice.payment_intent'],
      metadata: {
        userId: user._id.toString()
      }
    };
    
    // Add coupon if provided
    if (couponId) {
      subscriptionParams.coupon = couponId;
    }
    
    // Add trial period if provided
    if (trialDays && trialDays > 0) {
      const trialEnd = Math.floor(Date.now() / 1000) + (trialDays * 24 * 60 * 60);
      subscriptionParams.trial_end = trialEnd;
    }
    
    // Create the subscription
    const subscription = await stripeClient.subscriptions.create(subscriptionParams);
    
    // Get the price details to save in our database
    const price = await stripeClient.prices.retrieve(priceId, {
      expand: ['product']
    });
    
    // Determine the billing details
    const billingDetails = {
      interval: price.recurring.interval,
      intervalCount: price.recurring.interval_count,
      amount: price.unit_amount,
      currency: price.currency,
      productName: price.product.name,
      productId: price.product.id
    };
    
    // Save subscription details to user
    user.subscriptionId = subscription.id;
    user.subscriptionStatus = subscription.status;
    user.subscriptionPeriodEnd = new Date(subscription.current_period_end * 1000);
    user.subscriptionPriceId = priceId;
    user.subscriptionBillingDetails = billingDetails;
    
    // If there's a payment due now, record it
    if (subscription.latest_invoice && 
        subscription.latest_invoice.payment_intent &&
        subscription.latest_invoice.payment_intent.status === 'succeeded') {
      
      user.paymentHistory.push({
        paymentIntentId: subscription.latest_invoice.payment_intent.id,
        amount: subscription.latest_invoice.amount_paid,
        currency: subscription.latest_invoice.currency,
        status: 'succeeded',
        paymentMethodId: selectedPaymentMethodId,
        paymentMethodLast4: paymentMethod.card.last4,
        subscriptionId: subscription.id,
        invoiceId: subscription.latest_invoice.id
      });
    }
    
    await user.save();
    
    // Return subscription details to client
    res.status(201).json({
      message: 'Subscription created successfully',
      subscription: {
        id: subscription.id,
        status: subscription.status,
        currentPeriodEnd: new Date(subscription.current_period_end * 1000),
        billingDetails,
        paymentMethod: {
          id: paymentMethod.id,
          brand: paymentMethod.card.brand,
          last4: paymentMethod.card.last4
        }
      }
    });
    
  } catch (error) {
    console.error('Subscription creation error:', error);
    
    // Handle specific Stripe errors
    if (error.type === 'StripeCardError') {
      return res.status(400).json({ 
        message: 'Payment method declined', 
        error: error.message 
      });
    }
    
    res.status(500).json({ 
      message: 'Error creating subscription', 
      error: error.message 
    });
  }
});

// Cancel Subscription API
app.post('/subscriptions/cancel', authenticateToken, async (req, res) => {
  const { cancelImmediately = false } = req.body;
  
  try {
    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    if (!user.subscriptionId) {
      return res.status(400).json({ message: 'No active subscription found' });
    }
    
    const subscription = await stripeClient.subscriptions.retrieve(user.subscriptionId);
    
    // Cancel the subscription
    const canceledSubscription = await stripeClient.subscriptions.update(
      user.subscriptionId,
      {
        cancel_at_period_end: !cancelImmediately
      }
    );
    
    if (cancelImmediately) {
      // If canceling immediately, fully cancel the subscription
      await stripeClient.subscriptions.cancel(user.subscriptionId);
      
      // Update user record immediately
      user.subscriptionStatus = 'canceled';
      await user.save();
      
      res.status(200).json({
        message: 'Subscription canceled immediately',
        subscription: {
          id: user.subscriptionId,
          status: 'canceled'
        }
      });
    } else {
      // If canceling at period end, update the user record
      user.subscriptionStatus = 'active'; // Still active until period end
      user.cancelAtPeriodEnd = true;
      await user.save();
      
      res.status(200).json({
        message: 'Subscription will be canceled at the end of the billing period',
        subscription: {
          id: user.subscriptionId,
          status: 'active',
          cancelAtPeriodEnd: true,
          currentPeriodEnd: new Date(canceledSubscription.current_period_end * 1000)
        }
      });
    }
  } catch (error) {
    console.error('Subscription cancellation error:', error);
    res.status(500).json({ 
      message: 'Error canceling subscription', 
      error: error.message 
    });
  }
});

// Get Subscription Details API
app.get('/subscriptions/current', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    if (!user.subscriptionId) {
      return res.status(404).json({ 
        message: 'No subscription found',
        hasSubscription: false
      });
    }
    
    // Get fresh subscription data from Stripe
    const subscription = await stripeClient.subscriptions.retrieve(user.subscriptionId, {
      expand: ['default_payment_method', 'items.data.price.product']
    });
    
    // Get upcoming invoice if subscription is active
    let upcomingInvoice = null;
    if (subscription.status === 'active' || subscription.status === 'trialing') {
      try {
        upcomingInvoice = await stripeClient.invoices.retrieveUpcoming({
          customer: user.customerId,
          subscription: user.subscriptionId
        });
      } catch (err) {
        console.error('Error fetching upcoming invoice:', err);
      }
    }
    
    res.status(200).json({
      subscription: {
        id: subscription.id,
        status: subscription.status,
        currentPeriodStart: new Date(subscription.current_period_start * 1000),
        currentPeriodEnd: new Date(subscription.current_period_end * 1000),
        cancelAtPeriodEnd: subscription.cancel_at_period_end,
        canceledAt: subscription.canceled_at ? new Date(subscription.canceled_at * 1000) : null,
        product: subscription.items.data[0]?.price.product.name || 'Subscription',
        price: {
          amount: subscription.items.data[0]?.price.unit_amount / 100,
          currency: subscription.items.data[0]?.price.currency,
          interval: subscription.items.data[0]?.price.recurring.interval,
          intervalCount: subscription.items.data[0]?.price.recurring.interval_count
        },
        paymentMethod: subscription.default_payment_method ? {
          id: subscription.default_payment_method.id,
          brand: subscription.default_payment_method.card.brand,
          last4: subscription.default_payment_method.card.last4,
          expMonth: subscription.default_payment_method.card.exp_month,
          expYear: subscription.default_payment_method.card.exp_year
        } : null,
        upcomingInvoice: upcomingInvoice ? {
          amount: upcomingInvoice.amount_due / 100,
          currency: upcomingInvoice.currency,
          date: new Date(upcomingInvoice.next_payment_attempt * 1000)
        } : null
      }
    });
  } catch (error) {
    console.error('Subscription details error:', error);
    res.status(500).json({ 
      message: 'Error fetching subscription details', 
      error: error.message 
    });
  }
});

// Update Subscription Payment Method API
app.post('/subscriptions/update-payment', authenticateToken, async (req, res) => {
  const { paymentMethodId } = req.body;
  
  if (!paymentMethodId) {
    return res.status(400).json({ message: 'Payment method ID is required' });
  }
  
  try {
    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    if (!user.subscriptionId) {
      return res.status(400).json({ message: 'No active subscription found' });
    }
    
    // Verify this payment method belongs to the customer
    const paymentMethod = await stripeClient.paymentMethods.retrieve(paymentMethodId);
    if (paymentMethod.customer !== user.customerId) {
      return res.status(403).json({ message: 'This payment method does not belong to your account' });
    }
    
    // Update the default payment method on the subscription
    const updatedSubscription = await stripeClient.subscriptions.update(
      user.subscriptionId,
      {
        default_payment_method: paymentMethodId
      }
    );
    
    res.status(200).json({
      message: 'Subscription payment method updated',
      subscription: {
        id: updatedSubscription.id,
        status: updatedSubscription.status,
        paymentMethod: {
          id: paymentMethod.id,
          brand: paymentMethod.card.brand,
          last4: paymentMethod.card.last4
        }
      }
    });
  } catch (error) {
    console.error('Subscription payment update error:', error);
    res.status(500).json({ 
      message: 'Error updating subscription payment method', 
      error: error.message 
    });
  }
});

// Change Subscription Plan API
app.post('/subscriptions/change-plan', authenticateToken, async (req, res) => {
  const { newPriceId, prorationBehavior = 'create_prorations' } = req.body;
  
  if (!newPriceId) {
    return res.status(400).json({ message: 'New price ID is required' });
  }
  
  try {
    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    if (!user.subscriptionId) {
      return res.status(400).json({ message: 'No active subscription found' });
    }
    
    // Get the subscription to find the subscription item ID
    const subscription = await stripeClient.subscriptions.retrieve(user.subscriptionId);
    
    if (!subscription.items.data.length) {
      return res.status(400).json({ message: 'No subscription items found' });
    }
    
    const subscriptionItemId = subscription.items.data[0].id;
    
    // Update the subscription with the new price
    const updatedSubscription = await stripeClient.subscriptions.update(
      user.subscriptionId,
      {
        proration_behavior: prorationBehavior,
        items: [{
          id: subscriptionItemId,
          price: newPriceId,
        }],
        expand: ['latest_invoice.payment_intent']
      }
    );
    
    // Get the new price details to save in our database
    const price = await stripeClient.prices.retrieve(newPriceId, {
      expand: ['product']
    });
    
    // Determine the billing details
    const billingDetails = {
      interval: price.recurring.interval,
      intervalCount: price.recurring.interval_count,
      amount: price.unit_amount,
      currency: price.currency,
      productName: price.product.name,
      productId: price.product.id
    };
    
    // Update subscription details in user record
    user.subscriptionPriceId = newPriceId;
    user.subscriptionBillingDetails = billingDetails;
    
    // If there's a payment due now, record it
    if (updatedSubscription.latest_invoice && 
        updatedSubscription.latest_invoice.payment_intent &&
        updatedSubscription.latest_invoice.payment_intent.status === 'succeeded') {
      
      user.paymentHistory.push({
        paymentIntentId: updatedSubscription.latest_invoice.payment_intent.id,
        amount: updatedSubscription.latest_invoice.amount_paid,
        currency: updatedSubscription.latest_invoice.currency,
        status: 'succeeded',
        paymentMethodId: updatedSubscription.default_payment_method,
        subscriptionId: updatedSubscription.id,
        invoiceId: updatedSubscription.latest_invoice.id
      });
    }
    
    await user.save();
    
    res.status(200).json({
      message: 'Subscription plan changed successfully',
      subscription: {
        id: updatedSubscription.id,
        status: updatedSubscription.status,
        currentPeriodEnd: new Date(updatedSubscription.current_period_end * 1000),
        billingDetails
      }
    });
  } catch (error) {
    console.error('Subscription plan change error:', error);
    res.status(500).json({ 
      message: 'Error changing subscription plan', 
      error: error.message 
    });
  }
});

// Get Available Subscription Plans API
app.get('/subscription-plans', async (req, res) => {
  try {
    // Retrieve all active prices with their products
    const prices = await stripeClient.prices.list({
      active: true,
      expand: ['data.product'],
      limit: 100
    });
    
    // Filter for subscription prices only
    const subscriptionPrices = prices.data.filter(price => 
      price.type === 'recurring' && 
      price.product.active
    );
    
    // Group prices by product
    const plans = {};
    
    subscriptionPrices.forEach(price => {
      const product = price.product;
      const productId = product.id;
      
      if (!plans[productId]) {
        plans[productId] = {
          productId,
          name: product.name,
          description: product.description,
          features: product.metadata?.features ? JSON.parse(product.metadata.features) : [],
          prices: []
        };
      }
      
      plans[productId].prices.push({
        priceId: price.id,
        amount: price.unit_amount / 100,
        currency: price.currency,
        interval: price.recurring.interval,
        intervalCount: price.recurring.interval_count,
        trialPeriodDays: price.recurring.trial_period_days || 0
      });
    });
    
    res.status(200).json({
      plans: Object.values(plans)
    });
  } catch (error) {
    console.error('Error fetching subscription plans:', error);
    res.status(500).json({ 
      message: 'Error fetching subscription plans', 
      error: error.message 
    });
  }
});

// Add these handler functions:
async function handleSubscriptionCreated(subscription) {
  if (!subscription.customer) return;
  
  try {
    // Find the user by customerId
    const user = await User.findOne({ customerId: subscription.customer });
    if (!user) {
      console.error(`No user found for customer ID: ${subscription.customer}`);
      return;
    }
    
    // Update user's subscription data
    user.subscriptionId = subscription.id;
    user.subscriptionStatus = subscription.status;
    user.subscriptionPeriodEnd = new Date(subscription.current_period_end * 1000);
    
    await user.save();
    console.log(`Subscription ${subscription.id} created for user ${user.email}`);
  } catch (err) {
    console.error(`Error handling subscription created: ${err.message}`);
    throw err;
  }
}

async function handleSubscriptionUpdated(subscription) {
  if (!subscription.customer) return;
  
  try {
    // Find the user by customerId
    const user = await User.findOne({ customerId: subscription.customer });
    if (!user) {
      console.error(`No user found for customer ID: ${subscription.customer}`);
      return;
    }
    
    // Update user's subscription data
    user.subscriptionStatus = subscription.status;
    user.subscriptionPeriodEnd = new Date(subscription.current_period_end * 1000);
    user.cancelAtPeriodEnd = subscription.cancel_at_period_end;
    
    await user.save();
    console.log(`Subscription ${subscription.id} updated for user ${user.email}`);
  } catch (err) {
    console.error(`Error handling subscription updated: ${err.message}`);
    throw err;
  }
}

async function handleSubscriptionCanceled(subscription) {
  if (!subscription.customer) return;
  
  try {
    // Find the user by customerId
    const user = await User.findOne({ customerId: subscription.customer });
    if (!user) {
      console.error(`No user found for customer ID: ${subscription.customer}`);
      return;
    }
    
    // Update user's subscription data
    user.subscriptionStatus = 'canceled';
    user.cancelAtPeriodEnd = false;
    
    await user.save();
    console.log(`Subscription ${subscription.id} canceled for user ${user.email}`);
  } catch (err) {
    console.error(`Error handling subscription canceled: ${err.message}`);
    throw err;
  }
}

async function handleInvoicePaid(invoice) {
  if (!invoice.customer || !invoice.subscription) return;
  
  try {
    // Find the user by customerId
    const user = await User.findOne({ customerId: invoice.customer });
    if (!user) {
      console.error(`No user found for customer ID: ${invoice.customer}`);
      return;
    }
    
    // Check if this payment is already recorded
    const existingPayment = user.paymentHistory.find(p => 
      p.invoiceId === invoice.id
    );
    
    if (existingPayment) {
      console.log(`Invoice ${invoice.id} already recorded for user ${user.email}`);
      return;
    }
    
    // Get payment method details
    let paymentMethodLast4 = 'unknown';
    let paymentMethodId = invoice.default_payment_method || null;
    
    if (paymentMethodId) {
      try {
        const paymentMethod = await stripeClient.paymentMethods.retrieve(paymentMethodId);
        paymentMethodLast4 = paymentMethod.card?.last4 || 'unknown';
      } catch (err) {
        console.error(`Error retrieving payment method: ${err.message}`);
      }
    }
    
    // Record the payment
    user.paymentHistory.push({
      paymentIntentId: invoice.payment_intent,
      invoiceId: invoice.id,
      amount: invoice.amount_paid,
      currency: invoice.currency,
      status: 'succeeded',
      paymentMethodId: paymentMethodId,
      paymentMethodLast4: paymentMethodLast4,
      subscriptionId: invoice.subscription,
      createdAt: new Date(invoice.created * 1000)
    });
    
    // Update subscription status if needed
    if (user.subscriptionId === invoice.subscription) {
      user.subscriptionStatus = 'active';
      user.subscriptionPeriodEnd = new Date(invoice.lines.data[0]?.period.end * 1000);
    }
    
    await user.save();
    console.log(`Invoice ${invoice.id} recorded for user ${user.email}`);
  } catch (err) {
    console.error(`Error handling invoice paid: ${err.message}`);
    throw err;
  }
}

async function handleInvoicePaymentFailed(invoice) {
  if (!invoice.customer || !invoice.subscription) return;
  
  try {
    // Find the user by customerId
    const user = await User.findOne({ customerId: invoice.customer });
    if (!user) {
      console.error(`No user found for customer ID: ${invoice.customer}`);
      return;
    }
    
    // Update subscription status
    if (user.subscriptionId === invoice.subscription) {
      user.subscriptionStatus = 'past_due';
    }
    
    await user.save();
    console.log(`Subscription ${invoice.subscription} payment failed for user ${user.email}`);
  } catch (err) {
    console.error(`Error handling invoice payment failed: ${err.message}`);
    throw err;
  }
}

// Create subscription plan API
app.post('/admin/subscription-plans', authenticateToken, async (req, res) => {
  try {
    // Only allow the current user (assuming they're an admin)
    const user = await User.findById(req.user.userId);
    if (!user || user.role !== 'admin') {
      return res.status(403).json({ message: 'Unauthorized. Admin access required.' });
    }

    const { 
      name, 
      description, 
      amount, 
      currency = 'usd', 
      interval = 'month', 
      intervalCount = 1,
      trialDays = 0,
      features = [],
      active = true
    } = req.body;

    // Validate required fields
    if (!name || !amount) {
      return res.status(400).json({ message: 'Name and amount are required' });
    }

    // Create product in Stripe
    const product = await stripeClient.products.create({
      name,
      description,
      active,
      metadata: {
        features: JSON.stringify(features),
        createdBy: user._id.toString()
      }
    });

    // Create price for the product
    const price = await stripeClient.prices.create({
      product: product.id,
      unit_amount: Math.round(amount * 100), // Convert to cents
      currency,
      recurring: {
        interval,
        interval_count: intervalCount,
        trial_period_days: trialDays > 0 ? trialDays : undefined
      }
    });

    // Save plan to database for easy retrieval
    const newPlan = await SubscriptionPlan.create({
      name,
      description,
      productId: product.id,
      priceId: price.id,
      amount,
      currency,
      interval,
      intervalCount,
      trialDays,
      features,
      active,
      createdBy: user._id
    });

    res.status(201).json({
      message: 'Subscription plan created successfully',
      plan: {
        id: newPlan._id,
        name,
        productId: product.id,
        priceId: price.id,
        amount,
        currency,
        interval,
        intervalCount,
        trialDays,
        features,
        active
      }
    });
  } catch (error) {
    console.error('Error creating subscription plan:', error);
    res.status(500).json({ 
      message: 'Error creating subscription plan', 
      error: error.message 
    });
  }
});

// Delete User Account API
app.delete('/user/account', authenticateToken, async (req, res) => {
  try {
    const { password, deleteReason } = req.body;
    
    // Find the user
    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    // Verify password if provided
    if (password) {
      const passwordMatch = await bcrypt.compare(password, user.password);
      if (!passwordMatch) {
        return res.status(401).json({ message: 'Invalid password' });
      }
    }
    
    // Cancel subscription if exists
    if (user.subscriptionId) {
      try {
        // Try to cancel the subscription
        await stripeClient.subscriptions.cancel(user.subscriptionId);
        console.log(`Subscription ${user.subscriptionId} canceled for user ${user.email}`);
      } catch (err) {
        console.error(`Error canceling subscription: ${err.message}`);
        // Continue with deletion even if subscription cancellation fails
      }
    }
    
    // Delete Stripe customer if exists
    if (user.customerId) {
      try {
        await stripeClient.customers.del(user.customerId);
        console.log(`Stripe customer ${user.customerId} deleted for user ${user.email}`);
      } catch (err) {
        console.error(`Error deleting Stripe customer: ${err.message}`);
        // Continue with deletion even if customer deletion fails
      }
    }
    
    // Create an anonymous record of the deletion if reason provided
    if (deleteReason) {
      await DeletedUserFeedback.create({
        reason: deleteReason,
        hadSubscription: !!user.subscriptionId,
        email: user.email.slice(0, 3) + '***@***' + user.email.split('@')[1].slice(-3), // Anonymized email
        createdAt: new Date()
      });
    }
    
    // Delete the user from the database
    await User.findByIdAndDelete(req.user.userId);
    
    res.status(200).json({ 
      message: 'User account deleted successfully' 
    });
  } catch (error) {
    console.error('Error deleting user account:', error);
    res.status(500).json({ 
      message: 'Error deleting user account', 
      error: error.message 
    });
  }
});

// Get plans created by current user
app.get('/admin/subscription-plans', authenticateToken, async (req, res) => {
  try {
    // Only allow the current user (assuming they're an admin)
    const user = await User.findById(req.user.userId);
    if (!user || user.role !== 'admin') {
      return res.status(403).json({ message: 'Unauthorized. Admin access required.' });
    }

    // Get all plans created by this user
    const plans = await SubscriptionPlan.find({ 
      createdBy: user._id 
    }).sort({ createdAt: -1 });

    res.status(200).json({
      count: plans.length,
      plans: plans.map(plan => ({
        id: plan._id,
        name: plan.name,
        description: plan.description,
        productId: plan.productId,
        priceId: plan.priceId,
        amount: plan.amount,
        currency: plan.currency,
        interval: plan.interval,
        intervalCount: plan.intervalCount,
        trialDays: plan.trialDays,
        features: plan.features,
        active: plan.active,
        createdAt: plan.createdAt
      }))
    });
  } catch (error) {
    console.error('Error fetching subscription plans:', error);
    res.status(500).json({ 
      message: 'Error fetching subscription plans', 
      error: error.message 
    });
  }
});

// Update subscription plan API
app.put('/admin/subscription-plans/:planId', authenticateToken, async (req, res) => {
  try {
    const { planId } = req.params;
    
    // Only allow the current user (assuming they're an admin)
    const user = await User.findById(req.user.userId);
    if (!user || user.role !== 'admin') {
      return res.status(403).json({ message: 'Unauthorized. Admin access required.' });
    }

    // Get the plan and check ownership
    const plan = await SubscriptionPlan.findById(planId);
    if (!plan) {
      return res.status(404).json({ message: 'Subscription plan not found' });
    }

    if (plan.createdBy.toString() !== user._id.toString()) {
      return res.status(403).json({ message: 'Unauthorized. You can only edit your own plans.' });
    }

    const { 
      name, 
      description, 
      features = [],
      active
    } = req.body;

    // Update Stripe product
    const updatedProduct = await stripeClient.products.update(
      plan.productId,
      {
        name: name || plan.name,
        description: description || plan.description,
        active: active !== undefined ? active : plan.active,
        metadata: {
          features: JSON.stringify(features.length ? features : plan.features)
        }
      }
    );

    // Update local plan
    const updatedPlan = await SubscriptionPlan.findByIdAndUpdate(
      planId,
      {
        name: name || plan.name,
        description: description || plan.description,
        features: features.length ? features : plan.features,
        active: active !== undefined ? active : plan.active
      },
      { new: true }
    );

    res.status(200).json({
      message: 'Subscription plan updated successfully',
      plan: {
        id: updatedPlan._id,
        name: updatedPlan.name,
        description: updatedPlan.description,
        productId: updatedPlan.productId,
        priceId: updatedPlan.priceId,
        amount: updatedPlan.amount,
        currency: updatedPlan.currency,
        interval: updatedPlan.interval,
        intervalCount: updatedPlan.intervalCount,
        trialDays: updatedPlan.trialDays,
        features: updatedPlan.features,
        active: updatedPlan.active
      }
    });
  } catch (error) {
    console.error('Error updating subscription plan:', error);
    res.status(500).json({ 
      message: 'Error updating subscription plan', 
      error: error.message 
    });
  }
});

// Seed initial subscription plan (admin only)
app.post('/admin/seed-default-plan', authenticateToken, async (req, res) => {
  try {
    // Only allow admin
    const user = await User.findById(req.user.userId);
    if (!user || user.role !== 'admin') {
      return res.status(403).json({ message: 'Unauthorized. Admin access required.' });
    }

    // Check if any plans exist
    const existingPlans = await SubscriptionPlan.countDocuments();
    if (existingPlans > 0) {
      return res.status(400).json({ 
        message: 'Default plans already exist',
        existingPlans
      });
    }

    // Create a few default plans
    const plans = [
      {
        name: 'Basic Plan',
        description: 'Essential features for small businesses',
        amount: 9.99,
        currency: 'usd',
        interval: 'month',
        features: ['Feature 1', 'Feature 2', 'Feature 3']
      },
      {
        name: 'Premium Plan',
        description: 'Advanced features for growing businesses',
        amount: 19.99,
        currency: 'usd',
        interval: 'month',
        features: ['Feature 1', 'Feature 2', 'Feature 3', 'Feature 4', 'Feature 5']
      },
      {
        name: 'Enterprise Plan',
        description: 'Complete solution for established businesses',
        amount: 49.99,
        currency: 'usd',
        interval: 'month',
        features: ['All Features', 'Priority Support', 'Custom Integrations']
      }
    ];

    const createdPlans = [];

    // Create each plan
    for (const planData of plans) {
      // Create product in Stripe
      const product = await stripeClient.products.create({
        name: planData.name,
        description: planData.description,
        active: true,
        metadata: {
          features: JSON.stringify(planData.features),
          createdBy: user._id.toString()
        }
      });

      // Create price for the product
      const price = await stripeClient.prices.create({
        product: product.id,
        unit_amount: Math.round(planData.amount * 100), // Convert to cents
        currency: planData.currency,
        recurring: {
          interval: planData.interval,
          interval_count: 1
        }
      });

      // Save plan to database
      const newPlan = await SubscriptionPlan.create({
        name: planData.name,
        description: planData.description,
        productId: product.id,
        priceId: price.id,
        amount: planData.amount,
        currency: planData.currency,
        interval: planData.interval,
        intervalCount: 1,
        features: planData.features,
        active: true,
        createdBy: user._id
      });

      createdPlans.push({
        id: newPlan._id,
        name: newPlan.name,
        priceId: price.id,
        amount: newPlan.amount
      });

      // Add to user's created plans
      await User.findByIdAndUpdate(
        user._id,
        { $push: { createdSubscriptionPlans: newPlan._id } }
      );
    }

    res.status(201).json({
      message: 'Default subscription plans created successfully',
      plans: createdPlans
    });
  } catch (error) {
    console.error('Error creating default plans:', error);
    res.status(500).json({ 
      message: 'Error creating default plans', 
      error: error.message 
    });
  }
});

// Seed initial subscription plan (user only)
app.post('/user/seed-default-plan', authenticateToken, async (req, res) => {
  try {
    // Ensure user exists
    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Check if user has already created plans
    const existingPlans = await SubscriptionPlan.countDocuments({ createdBy: user._id });
    if (existingPlans > 0) {
      return res.status(400).json({
        message: 'Default plans already exist for this user',
        existingPlans
      });
    }

    // Define default plans
    const plans = [
      {
        name: 'Basic Plan',
        description: 'Essential features for small businesses',
        amount: 9.99,
        currency: 'usd',
        interval: 'month',
        features: ['Feature 1', 'Feature 2', 'Feature 3']
      },
      {
        name: 'Premium Plan',
        description: 'Advanced features for growing businesses',
        amount: 19.99,
        currency: 'usd',
        interval: 'month',
        features: ['Feature 1', 'Feature 2', 'Feature 3', 'Feature 4', 'Feature 5']
      },
      {
        name: 'Enterprise Plan',
        description: 'Complete solution for established businesses',
        amount: 49.99,
        currency: 'usd',
        interval: 'month',
        features: ['All Features', 'Priority Support', 'Custom Integrations']
      }
    ];

    const createdPlans = [];

    // Create each plan
    for (const planData of plans) {
      // Create product in Stripe
      const product = await stripeClient.products.create({
        name: planData.name,
        description: planData.description,
        active: true,
        metadata: {
          features: JSON.stringify(planData.features),
          createdBy: user._id.toString()
        }
      });

      // Create price for the product
      const price = await stripeClient.prices.create({
        product: product.id,
        unit_amount: Math.round(planData.amount * 100), // Convert to cents
        currency: planData.currency,
        recurring: {
          interval: planData.interval,
          interval_count: 1
        }
      });

      // Save plan to database
      const newPlan = await SubscriptionPlan.create({
        name: planData.name,
        description: planData.description,
        productId: product.id,
        priceId: price.id,
        amount: planData.amount,
        currency: planData.currency,
        interval: planData.interval,
        intervalCount: 1,
        features: planData.features,
        active: true,
        createdBy: user._id
      });

      createdPlans.push({
        id: newPlan._id,
        name: newPlan.name,
        priceId: price.id,
        amount: newPlan.amount
      });

      // Add to user's created plans
      await User.findByIdAndUpdate(
          user._id,
          { $push: { createdSubscriptionPlans: newPlan._id } }
      );
    }

    res.status(201).json({
      message: 'Default subscription plans created successfully',
      plans: createdPlans
    });
  } catch (error) {
    console.error('Error creating default plans:', error);
    res.status(500).json({
      message: 'Error creating default plans',
      error: error.message
    });
  }
});

// Get user invoices API
app.get('/invoices', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Get invoices from Stripe
    const invoices = await stripeClient.invoices.list({
      customer: user.customerId,
      limit: 50,
      expand: ['data.charge', 'data.payment_intent', 'data.subscription']
    });

    // Format invoice data for response
    const formattedInvoices = invoices.data.map(invoice => ({
      id: invoice.id,
      number: invoice.number,
      description: invoice.description,
      status: invoice.status,
      amountDue: invoice.amount_due / 100,
      amountPaid: invoice.amount_paid / 100,
      amountRemaining: invoice.amount_remaining / 100,
      currency: invoice.currency,
      created: new Date(invoice.created * 1000),
      dueDate: invoice.due_date ? new Date(invoice.due_date * 1000) : null,
      periodStart: new Date(invoice.period_start * 1000),
      periodEnd: new Date(invoice.period_end * 1000),
      subscription: invoice.subscription ? {
        id: invoice.subscription.id,
        status: invoice.subscription.status
      } : null,
      paymentIntent: invoice.payment_intent ? {
        id: invoice.payment_intent.id,
        status: invoice.payment_intent.status
      } : null,
      receiptUrl: invoice.charge ? invoice.charge.receipt_url : null,
      hostedInvoiceUrl: invoice.hosted_invoice_url,
      pdf: invoice.invoice_pdf,
      isSubscription: !!invoice.subscription,
      lines: invoice.lines.data.map(line => ({
        description: line.description,
        amount: line.amount / 100,
        quantity: line.quantity,
        period: line.period ? {
          start: new Date(line.period.start * 1000),
          end: new Date(line.period.end * 1000)
        } : null,
        proration: line.proration
      }))
    }));

    res.status(200).json({
      count: formattedInvoices.length,
      invoices: formattedInvoices
    });
  } catch (error) {
    console.error('Error fetching invoices:', error);
    res.status(500).json({ 
      message: 'Error fetching invoices', 
      error: error.message 
    });
  }
});

// Add these invoice APIs before your app.listen line

// 1. Create a draft invoice (Admin only)
app.post('/admin/invoices/draft', authenticateToken, async (req, res) => {
  try {
    // Verify admin user
    const admin = await User.findById(req.user.userId);
    if (!admin || admin.role !== 'admin') {
      return res.status(403).json({ message: 'Unauthorized. Admin access required.' });
    }

    const { 
      customerEmail,
      description,
      items,
      metadata = {},
      dueDate = null
    } = req.body;

    // Validate required fields
    if (!customerEmail || !items || !items.length) {
      return res.status(400).json({ 
        message: 'Customer email and at least one item are required' 
      });
    }

    // Find or create customer
    let customer;
    try {
      // Try to find existing customer
      const customers = await stripeClient.customers.list({
        email: customerEmail,
        limit: 1
      });

      if (customers.data.length > 0) {
        customer = customers.data[0];
      } else {
        // Create new customer
        customer = await stripeClient.customers.create({
          email: customerEmail
        });
      }
    } catch (err) {
      return res.status(400).json({ 
        message: 'Error finding or creating customer',
        error: err.message
      });
    }

    // Create invoice items
    for (const item of items) {
      await stripeClient.invoiceItems.create({
        customer: customer.id,
        amount: Math.round(item.amount * 100), // Convert to cents
        currency: item.currency || 'usd',
        description: item.description,
        quantity: item.quantity || 1
      });
    }

    // Create draft invoice
    const invoiceParams = {
      customer: customer.id,
      auto_advance: false, // Don't automatically finalize
      collection_method: 'send_invoice',
      description: description,
      metadata: {
        ...metadata,
        createdBy: admin._id.toString()
      }
    };

    // Add due date if provided
    if (dueDate) {
      const dueDateTimestamp = Math.floor(new Date(dueDate).getTime() / 1000);
      invoiceParams.due_date = dueDateTimestamp;
    }

    const invoice = await stripeClient.invoices.create(invoiceParams);

    res.status(201).json({
      message: 'Draft invoice created successfully',
      invoice: {
        id: invoice.id,
        status: invoice.status,
        amountDue: invoice.amount_due / 100,
        currency: invoice.currency,
        customer: {
          id: customer.id,
          email: customer.email
        },
        items: invoice.lines.data.map(item => ({
          description: item.description,
          amount: item.amount / 100,
          quantity: item.quantity
        }))
      }
    });
  } catch (error) {
    console.error('Error creating draft invoice:', error);
    res.status(500).json({ 
      message: 'Error creating draft invoice', 
      error: error.message 
    });
  }
});

// 2. Finalize a draft invoice (Admin only)
app.post('/admin/invoices/:invoiceId/finalize', authenticateToken, async (req, res) => {
  try {
    // Verify admin user
    const admin = await User.findById(req.user.userId);
    if (!admin || admin.role !== 'admin') {
      return res.status(403).json({ message: 'Unauthorized. Admin access required.' });
    }

    const { invoiceId } = req.params;

    // Retrieve the invoice
    const invoice = await stripeClient.invoices.retrieve(invoiceId);
    
    // Check if invoice can be finalized
    if (invoice.status !== 'draft') {
      return res.status(400).json({ 
        message: `Invoice cannot be finalized. Current status: ${invoice.status}` 
      });
    }

    // Finalize the invoice
    const finalizedInvoice = await stripeClient.invoices.finalizeInvoice(invoiceId);

    res.status(200).json({
      message: 'Invoice finalized successfully',
      invoice: {
        id: finalizedInvoice.id,
        number: finalizedInvoice.number,
        amountDue: finalizedInvoice.amount_due / 100,
        currency: finalizedInvoice.currency,
        status: finalizedInvoice.status,
        hostedInvoiceUrl: finalizedInvoice.hosted_invoice_url
      }
    });
  } catch (error) {
    console.error('Error finalizing invoice:', error);
    res.status(500).json({ 
      message: 'Error finalizing invoice', 
      error: error.message 
    });
  }
});

// 3. Add invoice items to a draft invoice (Admin only)
app.post('/admin/invoices/:invoiceId/items', authenticateToken, async (req, res) => {
  try {
    // Verify admin user
    const admin = await User.findById(req.user.userId);
    if (!admin || admin.role !== 'admin') {
      return res.status(403).json({ message: 'Unauthorized. Admin access required.' });
    }

    const { invoiceId } = req.params;
    const { items } = req.body;

    if (!items || !items.length) {
      return res.status(400).json({ message: 'At least one item is required' });
    }

    // Retrieve the invoice
    const invoice = await stripeClient.invoices.retrieve(invoiceId);
    
    // Check if invoice is in draft status
    if (invoice.status !== 'draft') {
      return res.status(400).json({ 
        message: `Items can only be added to draft invoices. Current status: ${invoice.status}` 
      });
    }

    // Add items to the invoice
    const addedItems = [];
    for (const item of items) {
      const invoiceItem = await stripeClient.invoiceItems.create({
        customer: invoice.customer,
        amount: Math.round(item.amount * 100), // Convert to cents
        currency: item.currency || invoice.currency,
        description: item.description,
        quantity: item.quantity || 1,
        invoice: invoiceId
      });

      addedItems.push({
        id: invoiceItem.id,
        description: invoiceItem.description,
        amount: invoiceItem.amount / 100,
        quantity: invoiceItem.quantity
      });
    }

    // Get the updated invoice
    const updatedInvoice = await stripeClient.invoices.retrieve(invoiceId);

    res.status(200).json({
      message: 'Items added to invoice successfully',
      addedItems,
      invoice: {
        id: updatedInvoice.id,
        amountDue: updatedInvoice.amount_due / 100,
        currency: updatedInvoice.currency,
        status: updatedInvoice.status
      }
    });
  } catch (error) {
    console.error('Error adding items to invoice:', error);
    res.status(500).json({ 
      message: 'Error adding items to invoice', 
      error: error.message 
    });
  }
});

// 4. Delete an invoice item (Admin only)
app.delete('/admin/invoice-items/:itemId', authenticateToken, async (req, res) => {
  try {
    // Verify admin user
    const admin = await User.findById(req.user.userId);
    if (!admin || admin.role !== 'admin') {
      return res.status(403).json({ message: 'Unauthorized. Admin access required.' });
    }

    const { itemId } = req.params;

    // Delete the invoice item
    const deletedItem = await stripeClient.invoiceItems.del(itemId);

    res.status(200).json({
      message: 'Invoice item deleted successfully',
      deleted: deletedItem.deleted
    });
  } catch (error) {
    console.error('Error deleting invoice item:', error);
    res.status(500).json({ 
      message: 'Error deleting invoice item', 
      error: error.message 
    });
  }
});

// 5. Update customer billing details for an invoice
app.put('/admin/invoices/:invoiceId/customer-details', authenticateToken, async (req, res) => {
  try {
    // Verify admin user
    const admin = await User.findById(req.user.userId);
    if (!admin || admin.role !== 'admin') {
      return res.status(403).json({ message: 'Unauthorized. Admin access required.' });
    }

    const { invoiceId } = req.params;
    const { 
      name,
      email,
      phone,
      address
    } = req.body;

    // Retrieve the invoice
    const invoice = await stripeClient.invoices.retrieve(invoiceId);
    
    // Check if invoice is still modifiable
    if (invoice.status !== 'draft' && invoice.status !== 'open') {
      return res.status(400).json({ 
        message: `Invoice customer details can't be modified. Current status: ${invoice.status}` 
      });
    }

    // Update the customer
    const customerUpdateParams = {};
    if (name) customerUpdateParams.name = name;
    if (email) customerUpdateParams.email = email;
    if (phone) customerUpdateParams.phone = phone;
    if (address) customerUpdateParams.address = address;

    const updatedCustomer = await stripeClient.customers.update(
      invoice.customer,
      customerUpdateParams
    );

    res.status(200).json({
      message: 'Invoice customer details updated successfully',
      customerDetails: {
        name: updatedCustomer.name,
        email: updatedCustomer.email,
        phone: updatedCustomer.phone,
        address: updatedCustomer.address
      }
    });
  } catch (error) {
    console.error('Error updating invoice customer details:', error);
    res.status(500).json({ 
      message: 'Error updating invoice customer details', 
      error: error.message 
    });
  }
});

// 6. Send invoice reminder (Admin only)
app.post('/admin/invoices/:invoiceId/send-reminder', authenticateToken, async (req, res) => {
  try {
    // Verify admin user
    const admin = await User.findById(req.user.userId);
    if (!admin || admin.role !== 'admin') {
      return res.status(403).json({ message: 'Unauthorized. Admin access required.' });
    }

    const { invoiceId } = req.params;

    // Retrieve the invoice
    const invoice = await stripeClient.invoices.retrieve(invoiceId);
    
    // Check if invoice is open
    if (invoice.status !== 'open') {
      return res.status(400).json({ 
        message: `Reminder can only be sent for open invoices. Current status: ${invoice.status}` 
      });
    }

    // Send the invoice
    await stripeClient.invoices.sendInvoice(invoiceId);

    res.status(200).json({
      message: 'Invoice reminder sent successfully',
      invoice: {
        id: invoice.id,
        number: invoice.number,
        amountDue: invoice.amount_due / 100,
        dueDate: invoice.due_date ? new Date(invoice.due_date * 1000) : null
      }
    });
  } catch (error) {
    console.error('Error sending invoice reminder:', error);
    res.status(500).json({ 
      message: 'Error sending invoice reminder', 
      error: error.message 
    });
  }
});

// 7. Get customer's unpaid invoices
app.get('/invoices/unpaid', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Get unpaid invoices from Stripe
    const invoices = await stripeClient.invoices.list({
      customer: user.customerId,
      status: 'open',
      limit: 10
    });

    // Format invoice data for response
    const unpaidInvoices = invoices.data.map(invoice => ({
      id: invoice.id,
      number: invoice.number,
      description: invoice.description,
      amountDue: invoice.amount_due / 100,
      currency: invoice.currency,
      dueDate: invoice.due_date ? new Date(invoice.due_date * 1000) : null,
      created: new Date(invoice.created * 1000),
      hostedInvoiceUrl: invoice.hosted_invoice_url,
      isSubscription: !!invoice.subscription
    }));

    res.status(200).json({
      count: unpaidInvoices.length,
      totalAmountDue: unpaidInvoices.reduce((sum, inv) => sum + inv.amountDue, 0),
      currency: unpaidInvoices.length > 0 ? unpaidInvoices[0].currency : 'usd',
      invoices: unpaidInvoices
    });
  } catch (error) {
    console.error('Error fetching unpaid invoices:', error);
    res.status(500).json({ 
      message: 'Error fetching unpaid invoices', 
      error: error.message 
    });
  }
});

// 8. Update invoice metadata (Admin only)
app.put('/admin/invoices/:invoiceId/metadata', authenticateToken, async (req, res) => {
  try {
    // Verify admin user
    const admin = await User.findById(req.user.userId);
    if (!admin || admin.role !== 'admin') {
      return res.status(403).json({ message: 'Unauthorized. Admin access required.' });
    }

    const { invoiceId } = req.params;
    const { metadata } = req.body;

    if (!metadata || typeof metadata !== 'object') {
      return res.status(400).json({ message: 'Valid metadata object is required' });
    }

    // Update invoice metadata
    const updatedInvoice = await stripeClient.invoices.update(invoiceId, {
      metadata: {
        ...metadata,
        updatedBy: admin._id.toString(),
        updatedAt: new Date().toISOString()
      }
    });

    res.status(200).json({
      message: 'Invoice metadata updated successfully',
      invoice: {
        id: updatedInvoice.id,
        number: updatedInvoice.number,
        metadata: updatedInvoice.metadata
      }
    });
  } catch (error) {
    console.error('Error updating invoice metadata:', error);
    res.status(500).json({ 
      message: 'Error updating invoice metadata', 
      error: error.message 
    });
  }
});

// 9. Search invoices (Admin only)
app.get('/admin/invoices/search', authenticateToken, async (req, res) => {
  try {
    // Verify admin user
    const admin = await User.findById(req.user.userId);
    if (!admin || admin.role !== 'admin') {
      return res.status(403).json({ message: 'Unauthorized. Admin access required.' });
    }

    const { 
      query, 
      status, 
      startDate, 
      endDate,
      minAmount,
      maxAmount,
      limit = 25
    } = req.query;

    // Build search parameters
    const searchParams = {
      limit: Math.min(parseInt(limit), 100) // Cap at 100 results
    };

    // Add status filter if provided
    if (status && ['draft', 'open', 'paid', 'uncollectible', 'void'].includes(status)) {
      searchParams.status = status;
    }

    // Add date range if provided
    if (startDate || endDate) {
      searchParams.created = {};
      if (startDate) {
        searchParams.created.gte = Math.floor(new Date(startDate).getTime() / 1000);
      }
      if (endDate) {
        searchParams.created.lte = Math.floor(new Date(endDate).getTime() / 1000);
      }
    }

    // Get invoices from Stripe
    const invoices = await stripeClient.invoices.list(searchParams);

    // Filter further on client side for queries Stripe API doesn't support
    let filteredInvoices = invoices.data;

    // Apply additional filters not supported by Stripe API
    if (query) {
      const lowerQuery = query.toLowerCase();
      filteredInvoices = filteredInvoices.filter(invoice => 
        (invoice.number && invoice.number.toLowerCase().includes(lowerQuery)) ||
        (invoice.customer_email && invoice.customer_email.toLowerCase().includes(lowerQuery)) ||
        (invoice.customer_name && invoice.customer_name.toLowerCase().includes(lowerQuery)) ||
        (invoice.description && invoice.description.toLowerCase().includes(lowerQuery))
      );
    }

    // Apply amount filters
    if (minAmount !== undefined) {
      const minAmountCents = parseFloat(minAmount) * 100;
      filteredInvoices = filteredInvoices.filter(invoice => 
        invoice.amount_due >= minAmountCents
      );
    }

    if (maxAmount !== undefined) {
      const maxAmountCents = parseFloat(maxAmount) * 100;
      filteredInvoices = filteredInvoices.filter(invoice => 
        invoice.amount_due <= maxAmountCents
      );
    }

    // Format results
    const formattedInvoices = filteredInvoices.map(invoice => ({
      id: invoice.id,
      number: invoice.number,
      customerEmail: invoice.customer_email,
      customerName: invoice.customer_name,
      description: invoice.description,
      status: invoice.status,
      amountDue: invoice.amount_due / 100,
      currency: invoice.currency,
      created: new Date(invoice.created * 1000),
      dueDate: invoice.due_date ? new Date(invoice.due_date * 1000) : null
    }));

    res.status(200).json({
      count: formattedInvoices.length,
      invoices: formattedInvoices
    });
  } catch (error) {
    console.error('Error searching invoices:', error);
    res.status(500).json({ 
      message: 'Error searching invoices', 
      error: error.message 
    });
  }
});

// 10. Upcoming invoice preview for subscription
app.get('/subscriptions/:subscriptionId/upcoming-invoice', authenticateToken, async (req, res) => {
  try {
    const { subscriptionId } = req.params;
    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Verify this subscription belongs to the user
    if (user.subscriptionId !== subscriptionId) {
      return res.status(403).json({ message: 'This subscription does not belong to your account' });
    }

    // Retrieve upcoming invoice for the subscription
    const upcomingInvoice = await stripeClient.invoices.retrieveUpcoming({
      customer: user.customerId,
      subscription: subscriptionId
    });

    // Format invoice for response
    const formattedInvoice = {
      amountDue: upcomingInvoice.amount_due / 100,
      amountRemaining: upcomingInvoice.amount_remaining / 100,
      currency: upcomingInvoice.currency,
      nextPaymentAttempt: upcomingInvoice.next_payment_attempt ? 
        new Date(upcomingInvoice.next_payment_attempt * 1000) : null,
      periodStart: new Date(upcomingInvoice.period_start * 1000),
      periodEnd: new Date(upcomingInvoice.period_end * 1000),
      subscriptionProrationDate: upcomingInvoice.subscription_proration_date ? 
        new Date(upcomingInvoice.subscription_proration_date * 1000) : null,
      lines: upcomingInvoice.lines.data.map(line => ({
        description: line.description,
        amount: line.amount / 100,
        period: line.period ? {
          start: new Date(line.period.start * 1000),
          end: new Date(line.period.end * 1000)
        } : null,
        proration: line.proration,
        quantity: line.quantity
      }))
    };

    res.status(200).json({
      invoice: formattedInvoice
    });
  } catch (error) {
    console.error('Error retrieving upcoming invoice:', error);
    res.status(500).json({ 
      message: 'Error retrieving upcoming invoice', 
      error: error.message 
    });
  }
});

// Add these API endpoints before your app.listen line

// 1. Invoice Download API for Users
app.get('/invoices/:invoiceId/download', authenticateToken, async (req, res) => {
  try {
    const { invoiceId } = req.params;
    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Retrieve the invoice
    const invoice = await stripeClient.invoices.retrieve(invoiceId, {
      expand: ['customer']
    });
    
    // Verify this invoice belongs to the user
    if (invoice.customer.id !== user.customerId) {
      return res.status(403).json({ message: 'This invoice does not belong to your account' });
    }

    if (!invoice.invoice_pdf) {
      return res.status(404).json({ message: 'No PDF available for this invoice' });
    }

    // We can't download the PDF directly through the API
    // Instead, we'll redirect to Stripe's hosted PDF URL
    return res.redirect(invoice.invoice_pdf);
    
    /* Alternative approach if you want to proxy the PDF:
    const pdfResponse = await axios({
      method: 'get',
      url: invoice.invoice_pdf,
      responseType: 'stream'
    });
    
    // Set response headers
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="invoice-${invoice.number}.pdf"`);
    
    // Pipe the PDF stream to the response
    pdfResponse.data.pipe(res);
    */
  } catch (error) {
    console.error('Error downloading invoice:', error);
    res.status(500).json({ 
      message: 'Error downloading invoice', 
      error: error.message 
    });
  }
});

// 2. Detailed Invoice Statistics for Admin
app.get('/admin/statistics/invoices', authenticateToken, async (req, res) => {
  try {
    // Verify admin user
    const admin = await User.findById(req.user.userId);
    if (!admin || admin.role !== 'admin') {
      return res.status(403).json({ message: 'Unauthorized. Admin access required.' });
    }

    const { 
      period = '30days', // Options: 7days, 30days, 90days, year, all
      currency = 'usd'
    } = req.query;

    // Calculate start date based on period
    let startTimestamp;
    const now = Math.floor(Date.now() / 1000);
    
    switch (period) {
      case '7days':
        startTimestamp = now - (7 * 24 * 60 * 60);
        break;
      case '90days':
        startTimestamp = now - (90 * 24 * 60 * 60);
        break;
      case 'year':
        startTimestamp = now - (365 * 24 * 60 * 60);
        break;
      case 'all':
        startTimestamp = 0; // Beginning of time
        break;
      case '30days':
      default:
        startTimestamp = now - (30 * 24 * 60 * 60);
    }

    // Fetch invoices for each status
    const fetchInvoicesByStatus = async (status) => {
      return stripeClient.invoices.list({
        limit: 100,
        status,
        created: { gte: startTimestamp },
        currency
      });
    };

    const [paidInvoices, openInvoices, draftInvoices, uncollectibleInvoices, voidInvoices] = 
      await Promise.all([
        fetchInvoicesByStatus('paid'),
        fetchInvoicesByStatus('open'),
        fetchInvoicesByStatus('draft'),
        fetchInvoicesByStatus('uncollectible'),
        fetchInvoicesByStatus('void')
      ]);

    // Calculate totals
    const calculateTotalAmount = (invoices, amountField = 'amount_paid') => {
      return invoices.data.reduce((sum, inv) => sum + inv[amountField], 0) / 100;
    };

    // Group invoices by day for trend analysis
    const groupInvoicesByDay = (invoices) => {
      const dailyData = {};
      
      invoices.data.forEach(invoice => {
        const date = new Date(invoice.created * 1000).toISOString().split('T')[0];
        if (!dailyData[date]) {
          dailyData[date] = {
            count: 0,
            amount: 0
          };
        }
        dailyData[date].count += 1;
        dailyData[date].amount += invoice.amount_paid / 100;
      });
      
      // Convert to array and sort by date
      return Object.entries(dailyData)
        .map(([date, data]) => ({ date, ...data }))
        .sort((a, b) => a.date.localeCompare(b.date));
    };

    // Calculate average invoice amount
    const calculateAverageAmount = (invoices, amountField = 'amount_paid') => {
      if (invoices.data.length === 0) return 0;
      return calculateTotalAmount(invoices, amountField) / invoices.data.length;
    };

    // Compile statistics
    const statistics = {
      currency: currency.toUpperCase(),
      period,
      overview: {
        totalPaid: calculateTotalAmount(paidInvoices),
        totalOutstanding: calculateTotalAmount(openInvoices, 'amount_due'),
        totalUncollectible: calculateTotalAmount(uncollectibleInvoices, 'amount_due'),
        totalVoided: calculateTotalAmount(voidInvoices, 'amount_due'),
        avgInvoiceAmount: calculateAverageAmount(paidInvoices),
        conversionRate: openInvoices.data.length > 0 ? 
          (paidInvoices.data.length / (paidInvoices.data.length + openInvoices.data.length)) * 100 : 100
      },
      counts: {
        paid: paidInvoices.data.length,
        open: openInvoices.data.length,
        draft: draftInvoices.data.length,
        uncollectible: uncollectibleInvoices.data.length,
        void: voidInvoices.data.length,
        total: paidInvoices.data.length + openInvoices.data.length + 
               draftInvoices.data.length + uncollectibleInvoices.data.length +
               voidInvoices.data.length
      },
      trends: {
        daily: groupInvoicesByDay(paidInvoices)
      },
      topInvoices: paidInvoices.data
        .sort((a, b) => b.amount_paid - a.amount_paid)
        .slice(0, 5)
        .map(invoice => ({
          id: invoice.id,
          number: invoice.number,
          amount: invoice.amount_paid / 100,
          customerEmail: invoice.customer_email,
          date: new Date(invoice.created * 1000)
        }))
    };

    res.status(200).json({ statistics });
  } catch (error) {
    console.error('Error generating invoice statistics:', error);
    res.status(500).json({ 
      message: 'Error generating invoice statistics', 
      error: error.message 
    });
  }
});

// 3. Comprehensive Payment Transaction Statistics for Admin
app.get('/admin/statistics/transactions', authenticateToken, async (req, res) => {
  try {
    // Verify admin user
    const admin = await User.findById(req.user.userId);
    if (!admin || admin.role !== 'admin') {
      return res.status(403).json({ message: 'Unauthorized. Admin access required.' });
    }

    const { 
      period = '30days', // Options: 7days, 30days, 90days, year, all
      currency = 'usd'
    } = req.query;

    // Calculate start date based on period
    let startTimestamp;
    const now = Math.floor(Date.now() / 1000);
    
    switch (period) {
      case '7days':
        startTimestamp = now - (7 * 24 * 60 * 60);
        break;
      case '90days':
        startTimestamp = now - (90 * 24 * 60 * 60);
        break;
      case 'year':
        startTimestamp = now - (365 * 24 * 60 * 60);
        break;
      case 'all':
        startTimestamp = 0; // Beginning of time
        break;
      case '30days':
      default:
        startTimestamp = now - (30 * 24 * 60 * 60);
    }

    // Fetch different types of transactions
    const fetchChargesByStatus = async (status) => {
      return stripeClient.charges.list({
        limit: 100,
        created: { gte: startTimestamp },
        currency
      }).then(result => {
        return result.data.filter(charge => charge.status === status);
      });
    };

    const fetchPaymentIntentsByStatus = async (status) => {
      return stripeClient.paymentIntents.list({
        limit: 100,
        created: { gte: startTimestamp },
        currency
      }).then(result => {
        return result.data.filter(pi => pi.status === status);
      });
    };

    const fetchRefunds = async () => {
      return stripeClient.refunds.list({
        limit: 100,
        created: { gte: startTimestamp }
      });
    };

    const fetchDisputes = async () => {
      return stripeClient.disputes.list({
        limit: 100,
        created: { gte: startTimestamp }
      });
    };

    const fetchSubscriptionEvents = async () => {
      return stripeClient.events.list({
        limit: 100,
        created: { gte: startTimestamp },
        type: 'customer.subscription.created'
      });
    };

    // Execute all queries in parallel
    const [
      successfulCharges,
      failedCharges,
      successfulPaymentIntents,
      failedPaymentIntents,
      refunds,
      disputes,
      subscriptionEvents
    ] = await Promise.all([
      fetchChargesByStatus('succeeded'),
      fetchChargesByStatus('failed'),
      fetchPaymentIntentsByStatus('succeeded'),
      fetchPaymentIntentsByStatus('canceled'),
      fetchRefunds(),
      fetchDisputes(),
      fetchSubscriptionEvents()
    ]);

    // Get order information from DB
    const orders = await User.aggregate([
      { $unwind: '$orders' },
      { $match: { 'orders.createdAt': { $gte: new Date(startTimestamp * 1000) } } },
      { $project: { 
          _id: 0,
          orderId: '$orders.orderId',
          totalAmount: '$orders.totalAmount',
          currency: '$orders.currency',
          status: '$orders.status',
          createdAt: '$orders.createdAt'
        }
      }
    ]);

    // Calculate totals for each transaction type
    const calculateTotal = (transactions, amountField = 'amount') => {
      return transactions.reduce((sum, tx) => sum + tx[amountField], 0) / 100;
    };

    // Group transactions by day for trend analysis
    const groupTransactionsByDay = (transactions, amountField = 'amount') => {
      const dailyData = {};
      
      transactions.forEach(tx => {
        const date = new Date(tx.created * 1000).toISOString().split('T')[0];
        if (!dailyData[date]) {
          dailyData[date] = {
            count: 0,
            amount: 0
          };
        }
        dailyData[date].count += 1;
        dailyData[date].amount += tx[amountField] / 100;
      });
      
      // Convert to array and sort by date
      return Object.entries(dailyData)
        .map(([date, data]) => ({ date, ...data }))
        .sort((a, b) => a.date.localeCompare(b.date));
    };

    // Group orders by day
    const groupOrdersByDay = (ordersList) => {
      const dailyData = {};
      
      ordersList.forEach(order => {
        const date = new Date(order.createdAt).toISOString().split('T')[0];
        if (!dailyData[date]) {
          dailyData[date] = {
            count: 0,
            amount: 0
          };
        }
        dailyData[date].count += 1;
        dailyData[date].amount += order.totalAmount / 100;
      });
      
      return Object.entries(dailyData)
        .map(([date, data]) => ({ date, ...data }))
        .sort((a, b) => a.date.localeCompare(b.date));
    };

    // Classify transactions by payment method
    const classifyByPaymentMethod = (charges) => {
      const methodStats = {};
      
      charges.forEach(charge => {
        const method = charge.payment_method_details?.card?.brand || 'unknown';
        if (!methodStats[method]) {
          methodStats[method] = {
            count: 0,
            amount: 0
          };
        }
        methodStats[method].count += 1;
        methodStats[method].amount += charge.amount / 100;
      });
      
      return methodStats;
    };

    // Compile statistics
    const statistics = {
      currency: currency.toUpperCase(),
      period,
      overview: {
        totalProcessed: calculateTotal(successfulCharges),
        totalFailed: calculateTotal(failedCharges),
        totalRefunded: calculateTotal(refunds.data, 'amount'),
        totalDisputed: calculateTotal(disputes.data, 'amount'),
        successRate: (successfulCharges.length + failedCharges.length) > 0 ?
          (successfulCharges.length / (successfulCharges.length + failedCharges.length)) * 100 : 0,
        refundRate: successfulCharges.length > 0 ?
          (refunds.data.length / successfulCharges.length) * 100 : 0,
        averageOrderValue: orders.length > 0 ?
          orders.reduce((sum, order) => sum + order.totalAmount, 0) / 100 / orders.length : 0
      },
      counts: {
        successfulCharges: successfulCharges.length,
        failedCharges: failedCharges.length,
        refunds: refunds.data.length,
        disputes: disputes.data.length,
        orders: orders.length,
        subscriptions: subscriptionEvents.data.length
      },
      trends: {
        dailyCharges: groupTransactionsByDay(successfulCharges),
        dailyRefunds: groupTransactionsByDay(refunds.data),
        dailyOrders: groupOrdersByDay(orders)
      },
      paymentMethods: classifyByPaymentMethod(successfulCharges),
      transactionTypes: {
        orderPayments: {
          count: orders.length,
          amount: orders.reduce((sum, order) => sum + order.totalAmount, 0) / 100
        },
        subscriptionPayments: {
          count: subscriptionEvents.data.length,
          // We'd need to aggregate actual subscription amounts from your database
        },
        refunds: {
          count: refunds.data.length,
          amount: calculateTotal(refunds.data, 'amount')
        },
        disputes: {
          count: disputes.data.length,
          amount: calculateTotal(disputes.data, 'amount')
        }
      },
      recentTransactions: successfulCharges
        .sort((a, b) => b.created - a.created)
        .slice(0, 10)
        .map(charge => ({
          id: charge.id,
          amount: charge.amount / 100,
          currency: charge.currency,
          paymentMethod: charge.payment_method_details?.card?.brand || 'unknown',
          date: new Date(charge.created * 1000),
          description: charge.description || 'Payment'
        }))
    };

    res.status(200).json({ statistics });
  } catch (error) {
    console.error('Error generating transaction statistics:', error);
    res.status(500).json({ 
      message: 'Error generating transaction statistics', 
      error: error.message 
    });
  }
});

// 4. User Transaction History Statistics
app.get('/statistics/transactions', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Get all payment history for the user
    const paymentHistory = user.paymentHistory || [];
    
    // Get orders for the user
    const orders = user.orders || [];

    // Calculate total spent
    const totalSpent = paymentHistory.reduce((sum, payment) => {
      if (payment.status === 'succeeded') {
        return sum + payment.amount;
      }
      return sum;
    }, 0) / 100;

    // Group payments by month
    const monthlySpending = {};
    paymentHistory.forEach(payment => {
      if (payment.status === 'succeeded') {
        const date = new Date(payment.createdAt);
        const monthYear = `${date.getFullYear()}-${(date.getMonth() + 1).toString().padStart(2, '0')}`;
        
        if (!monthlySpending[monthYear]) {
          monthlySpending[monthYear] = 0;
        }
        monthlySpending[monthYear] += payment.amount / 100;
      }
    });

    // Convert to array and sort
    const spendingTrend = Object.entries(monthlySpending)
      .map(([month, amount]) => ({ month, amount }))
      .sort((a, b) => a.month.localeCompare(b.month));

    // Get subscription information
    const hasActiveSubscription = user.subscriptionStatus === 'active';
    
    // Compile statistics
    const statistics = {
      overview: {
        totalSpent,
        paymentCount: paymentHistory.filter(p => p.status === 'succeeded').length,
        orderCount: orders.length,
        hasSubscription: hasActiveSubscription,
        subscriptionStatus: user.subscriptionStatus,
        averageOrderValue: orders.length > 0 ?
          orders.reduce((sum, order) => sum + order.totalAmount, 0) / 100 / orders.length : 0
      },
      spendingTrend,
      paymentMethods: user.paymentMethods.map(pm => ({
        id: pm.paymentMethodId,
        brand: pm.brand,
        last4: pm.last4,
        isDefault: pm.isDefault
      })),
      recentPayments: paymentHistory
        .filter(p => p.status === 'succeeded')
        .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
        .slice(0, 5)
        .map(payment => ({
          date: payment.createdAt,
          amount: payment.amount / 100,
          currency: payment.currency,
          method: `${payment.paymentMethodLast4 ? '•••• ' + payment.paymentMethodLast4 : 'Unknown'}`
        }))
    };

    res.status(200).json({ statistics });
  } catch (error) {
    console.error('Error generating user transaction statistics:', error);
    res.status(500).json({ 
      message: 'Error generating user transaction statistics', 
      error: error.message 
    });
  }
});

// 5. Revenue Dashboard API for Admin
app.get('/admin/dashboard/revenue', authenticateToken, async (req, res) => {
  try {
    // Verify admin user
    const admin = await User.findById(req.user.userId);
    if (!admin || admin.role !== 'admin') {
      return res.status(403).json({ message: 'Unauthorized. Admin access required.' });
    }

    // Calculate date ranges
    const now = Math.floor(Date.now() / 1000);
    const today = now - (now % 86400); // Start of today
    const yesterday = today - 86400;
    const lastWeekStart = today - (7 * 86400);
    const lastMonthStart = today - (30 * 86400);
    const thisMonthStart = new Date();
    thisMonthStart.setDate(1);
    thisMonthStart.setHours(0, 0, 0, 0);
    const thisMonthStartTimestamp = Math.floor(thisMonthStart.getTime() / 1000);

    // Fetch charges for different time periods
    const fetchChargesForPeriod = async (startTime, endTime) => {
      const params = {
        limit: 100,
        created: { gte: startTime }
      };
      
      if (endTime) {
        params.created.lt = endTime;
      }
      
      const charges = await stripeClient.charges.list(params);
      return charges.data.filter(charge => charge.status === 'succeeded');
    };

    const [
      todayCharges,
      yesterdayCharges,
      thisWeekCharges,
      thisMonthCharges,
      lastMonthCharges
    ] = await Promise.all([
      fetchChargesForPeriod(today),
      fetchChargesForPeriod(yesterday, today),
      fetchChargesForPeriod(lastWeekStart),
      fetchChargesForPeriod(thisMonthStartTimestamp),
      fetchChargesForPeriod(lastMonthStart, thisMonthStartTimestamp)
    ]);

    // Calculate revenue for each period
    const calculateRevenue = (charges) => {
      const revenueByCurrency = {};
      
      charges.forEach(charge => {
        const currency = charge.currency.toUpperCase();
        if (!revenueByCurrency[currency]) {
          revenueByCurrency[currency] = 0;
        }
        revenueByCurrency[currency] += charge.amount / 100;
      });
      
      return revenueByCurrency;
    };

    // Get active subscriptions count
    const subscriptions = await stripeClient.subscriptions.list({
      limit: 100,
      status: 'active'
    });

    // Calculate recurring revenue (MRR)
    const calculateMRR = (activeSubscriptions) => {
      const mrrByCurrency = {};
      
      activeSubscriptions.data.forEach(sub => {
        const currency = sub.currency.toUpperCase();
        if (!mrrByCurrency[currency]) {
          mrrByCurrency[currency] = 0;
        }
        
        // Add the subscription amount to MRR
        // For yearly subs, divide by 12
        if (sub.items.data.length > 0) {
          const plan = sub.items.data[0].plan;
          let amount = plan.amount * sub.items.data[0].quantity / 100;
          
          if (plan.interval === 'year') {
            amount = amount / 12;
          } else if (plan.interval === 'week') {
            amount = amount * 4.33; // Approx weeks in a month
          } else if (plan.interval === 'day') {
            amount = amount * 30; // Approx days in a month
          }
          
          mrrByCurrency[currency] += amount;
        }
      });
      
      return mrrByCurrency;
    };

    // Compile dashboard data
    const dashboard = {
      revenue: {
        today: calculateRevenue(todayCharges),
        yesterday: calculateRevenue(yesterdayCharges),
        thisWeek: calculateRevenue(thisWeekCharges),
        thisMonth: calculateRevenue(thisMonthCharges),
        lastMonth: calculateRevenue(lastMonthCharges),
        growth: {}
      },
      transactions: {
        today: todayCharges.length,
        yesterday: yesterdayCharges.length,
        thisWeek: thisWeekCharges.length,
        thisMonth: thisMonthCharges.length,
        lastMonth: lastMonthCharges.length
      },
      subscriptions: {
        active: subscriptions.data.length,
        mrr: calculateMRR(subscriptions),
        averageValue: subscriptions.data.length > 0 ? 
          (subscriptions.data.reduce((sum, sub) => {
            const plan = sub.items.data[0]?.plan;
            if (!plan) return sum;
            return sum + (plan.amount * sub.items.data[0].quantity);
          }, 0) / 100 / subscriptions.data.length) : 0
      }
    };

    // Calculate growth rates
    Object.keys(dashboard.revenue.thisMonth).forEach(currency => {
      dashboard.revenue.growth[currency] = {
        dailyChange: yesterdayCharges.length > 0 ? 
          ((dashboard.revenue.today[currency] || 0) - (dashboard.revenue.yesterday[currency] || 0)) / 
          (dashboard.revenue.yesterday[currency] || 1) * 100 : 0,
        monthlyChange: dashboard.revenue.lastMonth[currency] ? 
          ((dashboard.revenue.thisMonth[currency] || 0) - (dashboard.revenue.lastMonth[currency] || 0)) / 
          (dashboard.revenue.lastMonth[currency] || 1) * 100 : 0
      };
    });

    res.status(200).json({ dashboard });
  } catch (error) {
    console.error('Error generating revenue dashboard:', error);
    res.status(500).json({ 
      message: 'Error generating revenue dashboard', 
      error: error.message 
    });
  }
});


// Keep your server listening code at the very bottom of the file
const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});