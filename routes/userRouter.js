import express from "express";
import bcrypt from "bcryptjs";
import User from "../models/user.js";
import authMiddleware from "../middleware/authMiddleware.js";

const router = express.Router();

// Get current user
router.get("/me", authMiddleware, async (req, res) => {
  const user = await User.findById(req.user.id).select("-password");
  res.json(user);
});

// Update profile fields
router.patch("/:id/name", authMiddleware, async (req, res) => {
  const user = await User.findByIdAndUpdate(
    req.params.id,
    { name: req.body.name },
    { new: true }
  );
  res.json(user);
});
router.patch("/:id/email", authMiddleware, async (req, res) => {
  const user = await User.findByIdAndUpdate(
    req.params.id,
    { email: req.body.email },
    { new: true }
  );
  res.json(user);
});
router.patch("/:id/gender", authMiddleware, async (req, res) => {
  const user = await User.findByIdAndUpdate(
    req.params.id,
    { gender: req.body.gender },
    { new: true }
  );
  res.json(user);
});
router.patch("/:id/phone", authMiddleware, async (req, res) => {
  const user = await User.findByIdAndUpdate(
    req.params.id,
    { phone: req.body.phone },
    { new: true }
  );
  res.json(user);
});
router.patch("/:id/password", authMiddleware, async (req, res) => {
  const hashed = await bcrypt.hash(req.body.password, 10);
  const user = await User.findByIdAndUpdate(
    req.params.id,
    { password: hashed },
    { new: true }
  );
  res.json(user);
});

// Mark onboarding as done
router.post("/:id/onboarding", authMiddleware, async (req, res) => {
  const user = await User.findByIdAndUpdate(
    req.params.id,
    { onboardingDone: true },
    { new: true }
  );
  res.json(user);
});

export default router;
