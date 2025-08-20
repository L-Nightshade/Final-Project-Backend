import express from "express";
import auth from "../middleware/authMiddleware.js";
import bcrypt from "bcryptjs";
import User from "../models/user.js";

const router = express.Router();

// Get current user
router.get("/me", auth, async (req, res) => {
  const user = await user.findById(req.user.id).select("-password");
  res.json(user);
});

// Update profile fields
router.patch("/:id/name", auth, async (req, res) => {
  const user = await User.findByIdAndUpdate(
    req.params.id,
    { name: req.body.name },
    { new: true }
  );
  res.json(user);
});
router.patch("/:id/email", auth, async (req, res) => {
  const user = await User.findByIdAndUpdate(
    req.params.id,
    { email: req.body.email },
    { new: true }
  );
  res.json(user);
});
router.patch("/:id/gender", auth, async (req, res) => {
  const user = await User.findByIdAndUpdate(
    req.params.id,
    { gender: req.body.gender },
    { new: true }
  );
  res.json(user);
});
router.patch("/:id/phone", auth, async (req, res) => {
  const user = await User.findByIdAndUpdate(
    req.params.id,
    { phone: req.body.phone },
    { new: true }
  );
  res.json(user);
});
router.patch("/:id/password", auth, async (req, res) => {
  const hashed = await bcrypt.hash(req.body.password, 10);
  const user = await User.findByIdAndUpdate(
    req.params.id,
    { password: hashed },
    { new: true }
  );
  res.json(user);
});

// Mark onboarding as done
router.post("/:id/onboarding", auth, async (req, res) => {
  const user = await User.findByIdAndUpdate(
    req.params.id,
    { onboardingDone: true },
    { new: true }
  );
  res.json(user);
});

export default router;
