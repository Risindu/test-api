const express = require('express');
const db = require('../models/db'); // Ensure the correct path to db.js
const router = express.Router();
const authenticateToken = require('../middleware/authenticateToken');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY); // Load Stripe Secret Key


// Route to create a Stripe Checkout Session
router.post('/driver/create-checkout-session', authenticateToken, async (req, res) => {
    const { fine_id, api_key } = req.body;

    try {
        // Validate API key
        if (api_key !== process.env.API_KEY) return res.status(400).send('Invalid API key.');

        // Step 1: Retrieve fine details for the given fine_id
        const [fineRows] = await db.execute(`
            SELECT fine_id, driver_id, amount, description, status FROM fines WHERE fine_id = ?
        `, [fine_id]);

        if (fineRows.length === 0) {
            return res.status(404).send('Fine not found.');
        }

        const fine = fineRows[0];

        if (fine.status === 'paid') {
            return res.status(400).send('This fine is already paid.');
        }

        // Step 2: Create a Stripe Checkout session
        const session = await stripe.checkout.sessions.create({
            payment_method_types: ['card'],
            line_items: [
                {
                    price_data: {
                        currency: 'usd',
                        product_data: {
                            name: `Fine Payment for Fine ID: ${fine.fine_id}`,
                        },
                        unit_amount: fine.amount * 100, // Stripe accepts amount in cents
                    },
                    quantity: 1,
                },
            ],
            mode: 'payment',
            success_url: `${process.env.FRONTEND_URL}/payment-success?session_id={CHECKOUT_SESSION_ID}`, // URL to redirect after successful payment
            cancel_url: `${process.env.FRONTEND_URL}/payment-cancel`, // URL to redirect if the payment is canceled
        });

        // Step 3: Return the session ID or URL to the Flutter frontend
        res.send({ sessionId: session.id, url: session.url });
    } catch (err) {
        console.error('Error details:', err);
        res.status(500).send('Failed to create checkout session.');
    }
});


const endpointSecret = process.env.STRIPE_WEBHOOK_SECRET;

// Stripe Webhook to handle payment success
router.post('/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
    const sig = req.headers['stripe-signature'];

    let event;

    try {
        event = stripe.webhooks.constructEvent(req.body, sig, endpointSecret);
    } catch (err) {
        console.error('Webhook signature verification failed:', err.message);
        return res.status(400).send('Webhook signature verification failed.');
    }

    // Handle the event
    switch (event.type) {
        case 'checkout.session.completed':
            const session = event.data.object;

            // Retrieve the fine_id from metadata (if needed)
            const fine_id = session.metadata.fine_id;

            // Step 1: Update the fine status to 'paid'
            await db.execute(`
                UPDATE fines SET status = 'paid' WHERE fine_id = ?
            `, [fine_id]);

            // Step 2: Store payment details in the payments table
            await db.execute(`
                INSERT INTO payments (fine_id, driver_id, amount, status, receipt_url, payment_date)
                VALUES (?, ?, ?, ?, ?, NOW())
            `, [fine_id, session.metadata.driver_id, session.amount_total / 100, 'succeeded', session.charges.data[0].receipt_url]);

            break;
        default:
            console.warn(`Unhandled event type ${event.type}`);
    }

    // Return 200 to acknowledge receipt of the event
    res.send({ received: true });
});


module.exports = router;