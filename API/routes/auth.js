const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('../models/db'); // Ensure the correct path to db.js
const db_license = require('../models/db_license'); // Ensure the correct path to db_license.js
const router = express.Router();
const crypto = require('crypto');
const qr = require('qrcode'); // For generating QR codes
const fs = require('fs'); // For file system operations
const path = require('path');
const authenticateToken = require('../middleware/authenticateToken');

// const nodemailer = require('nodemailer');

// Setup nodemailer transporter
// const transporter = nodemailer.createTransport({
//     service: 'Gmail',
//     auth: {
//         user: process.env.EMAIL_USER,
//         pass: process.env.EMAIL_PASS,
//     },
// });

router.post('/driver/login', async (req, res) => {
    const { username, password, api_key } = req.body;

    try {
        // Validate API key
        if (api_key !== process.env.API_KEY) return res.status(400).send('Invalid API key.');

        // Step 1: Check if the username exists in the driver table
        const [rows] = await db.execute('SELECT * FROM driver WHERE username = ?', [username]);
        if (rows.length === 0) return res.status(400).send('Invalid username or password.');

        const user = rows[0];

        // Step 2: Compare the entered password with the hashed password stored in the database
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(400).send('Invalid username or password.');

        // Step 3: Retrieve the notifications for the driver
        const [notifications] = await db.execute(`
            SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC
        `, [user.driver_id]);

        // Step 4: Generate a JWT token with a 15-minute expiration time
        const token = jwt.sign({ id: user.driver_id }, process.env.JWT_SECRET, { expiresIn: '15m' });

        // Step 5: Return the token, username, QR code path, profile picture, and notifications
        res.send({
            token,
            username: user.username,         // Return the username
            qr_code: user.qr_code,           // Return the stored QR code path
            profile_picture: user.profile_picture, // Return the stored profile picture path
            notifications                    // Return the notifications for the driver
        });
    } catch (err) {
        console.error('Error details:', err);
        res.status(500).send('Server error.');
    }
});


// Division Login Route
router.post('/division/login', async (req, res) => {
    const { email, password, api_key } = req.body;

    try {
        if(api_key !== process.env.API_KEY) return res.status(400).send('Invalid API key.');

        // Fetch division information using the email
        const [divisionRows] = await db.execute('SELECT * FROM police_division WHERE email = ?', [email]);
        if (divisionRows.length === 0) return res.status(400).send('Invalid division email.');
        const division = divisionRows[0];

        // Validate password
        const validPassword = await bcrypt.compare(password, division.password);
        if (!validPassword) return res.status(400).send('Invalid email or password.');

        // Generate token, expires in 15 minutes
        const token = jwt.sign({ id: division.division_id }, process.env.JWT_SECRET, { expiresIn: '15m' });

        // Fetch fines data for this division
        const [fineRows] = await db.execute(`
            SELECT 
                COUNT(*) AS total_fines,
                SUM(CASE WHEN status = 'paid' THEN 1 ELSE 0 END) AS paid_fines,
                SUM(CASE WHEN status = 'not paid' THEN 1 ELSE 0 END) AS remaining_fines,
                COUNT(CASE WHEN date >= DATE_SUB(CURDATE(), INTERVAL 2 MONTH) THEN 1 END) AS last_two_month_fines,
                COUNT(CASE WHEN YEAR(date) = YEAR(CURDATE()) THEN 1 END) AS this_year_fines
            FROM fines
            WHERE division_id = ?
        `, [division.division_id]);

        // Fetch this month's violation locations (hotspots)
        const [locationRows] = await db.execute(`
            SELECT lat, lon
            FROM fines
            WHERE division_id = ? 
            AND MONTH(date) = MONTH(CURDATE()) 
            AND YEAR(date) = YEAR(CURDATE())
        `, [division.division_id]);

        // Prepare the JSON response in the specified format
        const response = {
            token_id: token,
            division_name: division.division_name, // From the division table
            issued_fines: fineRows[0].total_fines,
            paid_fines: fineRows[0].paid_fines,
            remaining_fines: fineRows[0].remaining_fines,
            last_two_month_fines: fineRows[0].last_two_month_fines,
            this_year_fines: fineRows[0].this_year_fines,
            this_month_violation_hotspots: locationRows.map(loc => ({ lat: loc.lat, lon: loc.lon }))
        };

        res.json(response);
    } catch (err) {
        console.error(err);
        res.status(500).send('Server error.');
    }
});




// Driver Signup Route
router.post('/driver/signup', async (req, res) => {
    const { license_number, nic_number, username, email, password, division_name, api_key } = req.body;

    try {
        // Validate API key
        if (api_key !== process.env.API_KEY) return res.status(400).send('Invalid API key.');

        // Step 1: Verify License number and NIC in the License database
        const [licenseRows] = await db_license.execute(`
            SELECT * 
            FROM information 
            WHERE license_number = ? AND nic = ?
        `, [license_number, nic_number]);

        if (licenseRows.length === 0) {
            return res.status(404).send('License number and NIC do not match.');
        }

        // Step 2: Retrieve driver details from License database, including profile picture
        const licenseData = licenseRows[0];

        // Log licenseData for debugging
        console.log('License Data:', licenseData);

        // Validate that licenseData has all required fields
        if (!licenseData.surname || !licenseData.first_name || !licenseData.date_of_birth) {
            return res.status(400).send('Missing essential driver information.');
        }

        // Step 3: Check if the driver is already registered in the driver table
        const [existingDriver] = await db.execute(`
            SELECT * FROM driver WHERE license_number = ? OR nic_number = ?
        `, [license_number, nic_number]);

        if (existingDriver.length > 0) {
            return res.status(400).send('Driver already registered.');
        }

        // Step 4: Check if the division name exists and retrieve its division_id
        const [divisionRows] = await db.execute(`
            SELECT division_id FROM police_division WHERE division_name = ?
        `, [division_name]);

        if (divisionRows.length === 0) {
            return res.status(404).send('Division not found.');
        }

        const division_id = divisionRows[0].division_id; // Retrieve division_id

        // Step 5: Retrieve vehicle details from the vehicles_information table
        const [vehicleRows] = await db_license.execute(`
            SELECT * FROM vehicles_information WHERE license_number = ?
        `, [license_number]);

        // Step 6: Hash the password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Step 7: Generate a unique QR code for the driver
        const qrCodeData = `${license_number}_${nic_number}_${username}`;
        const qrCodePath = path.join(__dirname, '../qr_codes', `${license_number}.png`);

        await qr.toFile(qrCodePath, qrCodeData);

        // Step 8: Insert the driver's details into the driver table with division_id and profile_picture
        const [driverResult] = await db.execute(`
            INSERT INTO driver (license_number, nic_number, division_id, surname, firstname, middle_name, last_name, date_of_birth, date_of_issue, date_of_expiry, address, email, mobile_number, username, password, qr_code, profile_picture)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `, [
            licenseData.license_number,
            licenseData.nic,
            division_id,  // Store the division_id here
            licenseData.surname,
            licenseData.first_name,
            licenseData.middle_name || '', // Ensure a fallback if missing
            licenseData.last_name || '',   // Ensure a fallback if missing
            licenseData.date_of_birth,
            licenseData.date_of_issue,
            licenseData.date_of_expiry,
            licenseData.permenant_residence_address,
            licenseData.email,
            licenseData.mobile_number,
            username,
            hashedPassword,
            qrCodePath,    // Store the path to the QR code image
            licenseData.profile_picture // Store the profile picture path
        ]);

        // Step 9: Retrieve the driver_id of the newly inserted driver
        const driver_id = driverResult.insertId;

        // Step 10: Store vehicle data in the driver_vehicles table
        for (const vehicle of vehicleRows) {
            if (vehicle.vehicle_category && vehicle.date_of_issue && vehicle.date_of_expiry) {
                await db.execute(`
                    INSERT INTO driver_vehicles (driver_id, vehicle_category, vehicle_issue_date, vehicle_expiry_date)
                    VALUES (?, ?, ?, ?)
                `, [
                    driver_id,                 // Use the newly inserted driver_id
                    vehicle.vehicle_category,   // Vehicle category
                    vehicle.date_of_issue,      // Vehicle issue date
                    vehicle.date_of_expiry      // Vehicle expiry date
                ]);
            }
        }

        // Step 11: Return a success response
        res.send('Driver registered successfully.');
    } catch (err) {
        console.error('Error details:', err);
        res.status(500).send('Server error.');
    }
});


// Division Signup Route
router.post('/division/signup', async (req, res) => {
    const { division_id, division_name, email, location, password, api_key } = req.body;

    try {
        if(api_key !== process.env.API_KEY) return res.status(400).send('Invalid API key.');

        const [rows] = await db.execute('SELECT * FROM police_division WHERE division_id = ?', [division_id]);
        if (rows.length > 0) return res.status(400).send('Police division already registered.');

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        await db.execute('INSERT INTO police_division (division_id, division_name, email, location, password) VALUES (?, ?, ?, ?, ?)', [division_id, division_name, email, location, hashedPassword]);
        res.send('Police division registered successfully.');
    } catch (err) {
        console.error(err);
        res.status(500).send('Server error.');
    }
});


// Token Verification Route
router.post('/verify-token', (req, res) => {
    const { token } = req.body;

    if (!token) return res.sendStatus(401); // Unauthorized if no token is provided

    jwt.verify(token, process.env.JWT_SECRET, (err) => {
        if (err) return res.sendStatus(403); // Forbidden if token is invalid or expired
        res.sendStatus(200); // OK if token is valid
    });
});



// Fine Route for Driver
router.post('/driver/fines', async (req, res) => {
    const { driver_id, api_key } = req.body;

    try {
        // Validate API key
        if (api_key !== process.env.API_KEY) return res.status(400).send('Invalid API key.');

        // Step 1: Retrieve fine details for the given driver_id, excluding lat and lon
        const [fines] = await db.execute(`
            SELECT fine_id, driver_id, division_id, amount, description, category, status, date
            FROM fines
            WHERE driver_id = ?
        `, [driver_id]);

        if (fines.length === 0) {
            return res.status(404).send('No fines found for the provided driver_id.');
        }

        // Step 2: Return the fine details as the response
        res.send({ fines });
    } catch (err) {
        console.error('Error details:', err);
        res.status(500).send('Server error.');
    }
});


// Sample Protected Route
router.get('/protected', authenticateToken, (req, res) => {
    res.send('This is a protected route.');
});



module.exports = router;
