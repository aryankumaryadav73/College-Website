const express = require("express");
const nodemailer = require("nodemailer");
const cors = require("cors");
const crypto = require("crypto");
require("dotenv").config();

const app = express();

app.use(cors());
app.use(express.json());

const otpStore = new Map();
const sessionStore = new Map();

const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

app.post("/send-otp", async (req, res) => {

    const { email } = req.body;

    if (!email) {
        return res.status(400).json({
            success: false,
            message: "Email is required"
        });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();

otpStore.set(email, {
    otp: otp,
    expiresAt: Date.now() + 5 * 60 * 1000,
    attempts: 0
});

    try {

        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: email,
            subject: "College Website - OTP",
            html: `
                <h2>College Website</h2>
                <p>Your OTP is:</p>

                <h1>${otp}</h1>

                <p>This OTP is valid for 5 minutes.</p>

                <p>If you did not request this OTP, please ignore this email.</p>
            `
        });

        console.log(`OTP sent to ${email}`);

        res.json({
            success: true,
            message: "OTP sent successfully"
        });

    } catch (error) {

        console.error("Email error:", error);

        otpStore.delete(email);

        res.status(500).json({
            success: false,
            message: "Failed to send OTP"
        });
    }
});


app.post("/verify-otp", (req, res) => {

    const { email, otp } = req.body;

    const record = otpStore.get(email);

    if (!record) {
        return res.status(400).json({
            success: false,
            message: "OTP not found"
        });
    }

    if (Date.now() > record.expiresAt) {

        otpStore.delete(email);

        return res.status(400).json({
            success: false,
            message: "OTP expired"
        });
    }

    if (record.otp !== otp) {

    record.attempts++;

    if (record.attempts >= 3) {

        otpStore.delete(email);

        return res.status(400).json({
            success: false,
            message: "Too many incorrect attempts. Please request a new OTP."
        });
    }

    return res.status(400).json({
        success: false,
        message: `Invalid OTP. ${3 - record.attempts} attempts remaining.`
    });
}

    otpStore.delete(email);

const token = crypto.randomBytes(32).toString("hex");

sessionStore.set(token, {
    email: email,
    expiresAt: Date.now() + 24 * 60 * 60 * 1000
});

res.json({
    success: true,
    message: "OTP verified successfully",
    token: token,
    email: email
});
});
app.get("/check-session", (req, res) => {

    const token = req.headers.authorization;

    if (!token) {
        return res.status(401).json({
            success: false,
            message: "Not logged in"
        });
    }

    const session = sessionStore.get(token);

    if (!session) {
        return res.status(401).json({
            success: false,
            message: "Invalid session"
        });
    }

    if (Date.now() > session.expiresAt) {

        sessionStore.delete(token);

        return res.status(401).json({
            success: false,
            message: "Session expired"
        });
    }

    res.json({
        success: true,
        email: session.email
    });
});


// LOGOUT API
app.post("/logout", (req, res) => {
    const token = req.headers.authorization;

    if (!token) {
        return res.status(401).json({
            success: false,
            message: "No authentication token found"
        });
    }

    sessionStore.delete(token);

    res.json({
        success: true,
        message: "Logged out successfully"
    });
});



const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
