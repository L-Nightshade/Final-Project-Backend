import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import User from "../models/user.js";
import otpStore from "../utils/otpStore.js";

/**
 * Helpers
 */
const createToken = (user) => {
  const payload = { id: user._id, email: user.email };
  const secret = process.env.JWT_SECRETkey || "change_this_secret";
  return jwt.sign(payload, secret, { expiresIn: "7d" });
};

const normalizePhone = (body) => {
  // support both `phone` and `number` from different backends
  return body.phone || body.number || body.mobile || "";
};

/**
 * Register
 */
export const register = async (req, res) => {
  try {
    const name = req.body.name;
    const email = (req.body.email || "").toLowerCase();
    const phone = normalizePhone(req.body);
    const password = req.body.password;
    const gender = req.body.gender || null;

    if (!name || !email || !password || !phone) {
      return res.status(400).json({ message: "name, email, phone and password are required." });
    }

    // check existing user by email or phone
    const existing = await User.findOne({ $or: [{ email }, { phone }] });
    if (existing) {
      return res.status(409).json({ message: "User with given email or phone already exists." });
    }

    const hashed = await bcrypt.hash(password, 10);

    const user = await User.create({
      name,
      email,
      password: hashed,
      phone,
      gender,
    });

    const token = createToken(user);

    return res.status(201).json({
      message: "User registered",
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        phone: user.phone,
        gender: user.gender,
      },
      token,
    });
  } catch (err) {
    console.error("register error:", err);
    return res.status(500).json({ message: "Server error" });
  }
};

/**
 * Login
 * Accepts either email or phone in "identifier" (or email field) for compatibility
 */
export const login = async (req, res) => {
  try {
    const identifier = req.body.identifier || req.body.email || req.body.phone || req.body.number;
    const password = req.body.password;

    if (!identifier || !password) {
      return res.status(400).json({ message: "identifier and password required" });
    }

    // find by email or phone
    const query = identifier.includes("@") ? { email: identifier.toLowerCase() } : { phone: identifier };
    const user = await User.findOne(query);

    if (!user) return res.status(401).json({ message: "Invalid credentials" });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ message: "Invalid credentials" });

    const token = createToken(user);
    return res.json({
      message: "Login successful",
      user: { id: user._id, name: user.name, email: user.email, phone: user.phone, gender: user.gender },
      token,
    });
  } catch (err) {
    console.error("login error:", err);
    return res.status(500).json({ message: "Server error" });
  }
};

/**
 * Send OTP (for phone-based verification / password reset)
 * Stores OTP in otpStore; in production replace console.log with SMS provider
 */
export const sendOtp = async (req, res) => {
  try {
    const phone = normalizePhone(req.body);
    if (!phone) return res.status(400).json({ message: "phone (or number) required" });

    // 6-digit numeric OTP
    const code = ("" + Math.floor(100000 + Math.random() * 900000)).slice(0, 6);
    otpStore.save(phone, code, 5 * 60); // TTL 5 minutes

    // TODO: integrate SMS gateway here. For now, return/log the OTP for testing.
    console.log(`OTP for ${phone}: ${code}`);

    return res.json({ message: "OTP sent (in development it is logged to the server)." });
  } catch (err) {
    console.error("sendOtp error:", err);
    return res.status(500).json({ message: "Server error" });
  }
};

/**
 * Verify OTP
 */
export const verifyOtp = async (req, res) => {
  try {
    const phone = normalizePhone(req.body);
    const code = req.body.code;

    if (!phone || !code) return res.status(400).json({ message: "phone and code required" });

    const ok = otpStore.verify(phone, code);
    if (!ok) return res.status(400).json({ message: "Invalid or expired OTP" });

    // remove OTP after successful verification
    otpStore.delete(phone);

    return res.json({ message: "OTP verified" });
  } catch (err) {
    console.error("verifyOtp error:", err);
    return res.status(500).json({ message: "Server error" });
  }
};

/**
 * Reset Password
 * Accepts identifier (phone or email), otp, newPassword
 */
export const resetPassword = async (req, res) => {
  try {
    const identifier = req.body.identifier || req.body.email || req.body.phone || req.body.number;
    const otp = req.body.otp;
    const newPassword = req.body.newPassword;

    if (!identifier || !otp || !newPassword) {
      return res.status(400).json({ message: "identifier, otp and newPassword required" });
    }

    const phone = identifier.includes("@") ? null : identifier;
    const email = identifier.includes("@") ? identifier.toLowerCase() : null;

    // if phone provided, verify OTP
    if (phone) {
      if (!otpStore.verify(phone, otp)) {
        return res.status(400).json({ message: "Invalid or expired OTP" });
      }
    } else {
      // For email-based reset, you could implement token email flow. For now we require OTP-style (sent to phone).
      return res.status(400).json({ message: "Password reset via email not implemented; use phone OTP" });
    }

    // Find user
    const user = phone ? await User.findOne({ phone }) : await User.findOne({ email });
    if (!user) return res.status(404).json({ message: "User not found" });

    // update password
    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();

    // cleanup
    if (phone) otpStore.delete(phone);

    return res.json({ message: "Password reset successful" });
  } catch (err) {
    console.error("resetPassword error:", err);
    return res.status(500).json({ message: "Server error" });
  }
};
