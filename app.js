import express from "express";
import cors from "cors";
import mongoose from "mongoose";
import dotenv from "dotenv";

import authRouter from "./routes/authRouter.js";
import userRouter from "./routes/userRouter.js";

dotenv.config();
const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// Routes
app.use("/auth", authRouter);
app.use("/users", userRouter);

const port = process.env.PORT || 6000;

const start = async () => {
  try {
    await mongoose.connect(process.env.MONGO_URI);

    console.log("Database Connected");
    console.log("JWT_SECRET is:", process.env.JWT_SECRETkey);

    //     console.log("Skipping Database Connection till Mongo URI Is Available...");

    app.listen(port, () => {
      console.log(`Server running on PORT ${port}`);
    });
  } catch (err) {
    console.error("Connection failed:", err);
    process.exit(1); // stop app if DB fails
  }
};

start();
