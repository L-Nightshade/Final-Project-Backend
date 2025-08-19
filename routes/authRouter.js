// routes/authRouter.js
import express from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import User from "../models/user.js";
import otpStore from "../utils/otpStore.js";

const router = express.Router();

/**
 * Helpers
 */
const createToken = (user) => {
  const payload = { id: user._id, email: user.email };
  const secret = process.env.JWT_SECRETkey || "change_this_secret";
  return jwt.sign(payload, secret, { expiresIn: "3d" });
};

const normalizePhone = (body) => {
  return body.phone || body.number || "";
};

/**
 * Register
 */
router.post("/register", async (req, res) => {
  try {
    const { name, email, password, gender } = req.body;
    const phone = normalizePhone(req.body);

    if (!name || !email || !password || !phone) {
      return res.status(400).json({ message: "name, email, phone and password are required" });
    }

    // Check if user exists
    let existing = await User.findOne({ $or: [{ email }, { phone }] });
    if (existing) return res.status(400).json({ message: "User already exists" });

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create new user
    const user = new User({
      name,
      email: email.toLowerCase(),
      password: hashedPassword,
      gender,
      phone,
    });

    await user.save();

    const token = createToken(user);

    res.status(201).json({
      message: "User registered successfully",
      user,
      token,
    });
  } catch (err) {
    console.error("register error:", err);
    res.status(500).json({ message: err.message });
  }
});

/**
 * Login (supports email or phone)
 */
router.post("/login", async (req, res) => {
  try {
    const identifier = req.body.identifier || req.body.email || req.body.phone || req.body.number;
    const password = req.body.password;

    if (!identifier || !password) {
      return res.status(400).json({ message: "identifier and password required" });
    }

    const query = identifier.includes("@") ? { email: identifier.toLowerCase() } : { phone: identifier };
    const user = await User.findOne(query);

    if (!user) return res.status(400).json({ message: "Invalid credentials" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: "Invalid credentials" });

    const token = createToken(user);

    res.json({ token, user });
  } catch (err) {
    console.error("login error:", err);
    res.status(500).json({ message: err.message });
  }
});

/**
 * Send OTP (for phone verification / password reset)
 */
router.post("/otp/send", async (req, res) => {
  try {
    const phone = normalizePhone(req.body);
    if (!phone) return res.status(400).json({ message: "phone (or number) required" });

    const code = ("" + Math.floor(100000 + Math.random() * 900000)).slice(0, 6);
    otpStore.save(phone, code, 5 * 60);

    console.log(`OTP for ${phone}: ${code}`); // TODO: integrate SMS provider

    res.json({ message: "OTP sent (check server logs in dev mode)" });
  } catch (err) {
    console.error("sendOtp error:", err);
    res.status(500).json({ message: err.message });
  }
});

/**
 * Verify OTP
 */
router.post("/otp/verify", async (req, res) => {
  try {
    const phone = normalizePhone(req.body);
    const code = req.body.code;

    if (!phone || !code) return res.status(400).json({ message: "phone and code required" });

    const ok = otpStore.verify(phone, code);
    if (!ok) return res.status(400).json({ message: "Invalid or expired OTP" });

    otpStore.delete(phone);

    res.json({ message: "OTP verified" });
  } catch (err) {
    console.error("verifyOtp error:", err);
    res.status(500).json({ message: err.message });
  }
});

/**
 * Reset Password (phone + OTP)
 */
router.post("/reset", async (req, res) => {
  try {
    const identifier = req.body.identifier || req.body.email || req.body.phone || req.body.number;
    const otp = req.body.otp;
    const newPassword = req.body.newPassword;

    if (!identifier || !otp || !newPassword) {
      return res.status(400).json({ message: "identifier, otp and newPassword required" });
    }

    const phone = identifier.includes("@") ? null : identifier;

    if (phone) {
      if (!otpStore.verify(phone, otp)) {
        return res.status(400).json({ message: "Invalid or expired OTP" });
      }
    }

    const user = phone
      ? await User.findOne({ phone })
      : await User.findOne({ email: identifier.toLowerCase() });

    if (!user) return res.status(404).json({ message: "User not found" });

    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();

    if (phone) otpStore.delete(phone);

    res.json({ message: "Password reset successful" });
  } catch (err) {
    console.error("resetPassword error:", err);
    res.status(500).json({ message: err.message });
  }
});

/**
 * Forgot Password (email placeholder)
 */
router.post("/forgot-password", async (req, res) => {
  try {
    const { email } = req.body;
    res.json({ message: `Password reset link (mock) sent to ${email}` });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

/**
 * Logout
 */
router.post("/logout", (req, res) => {
  res.json({ message: "Logged out" });
});

export default router;
