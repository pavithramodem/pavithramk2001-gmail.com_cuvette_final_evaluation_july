const express = require("express");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const dotenv = require("dotenv");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const cors = require("cors");
dotenv.config();
const User = require("./models/user");
const app = express();
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(
  cors({
    origin: ["http://localhost:3000"],
    methods: ["GET", "POST"],
    credentials: true,
  })
);
app.get("/", (req, res) => {
  res.send("hello!");
});
app.get("/users", async (req, res) => {
  try {
    let users = await User.find({});
    res.json({
      message: "success",
      data: users,
    });
  } catch (error) {
    console.log(error);
    res.status(500).json({
      error: true,
      message: "Something went wrong",
    });
  }
});
app.post("/signup", async (req, res) => {
  try {
    const { name, email, password} = req.body;
    const encrypted = await bcrypt.hash(password, 10);
    // Check if the user with the given email already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      // If user exists, return an error message
      return res.status(400).json({
        error: true,
        message: "User with this email already exists",
      });
    }
    // Insert the new user into the collection
    await User.create({
      name,
      email,
      password: encrypted,
    });
    res.status(201).json({
      message: "User registered successfully!",
    });
  } catch (error) {
    console.error(error);
    if (error.code === 11000) {
      // Duplicate key error (unique constraint violation)
      res.status(400).json({
        error: true,
        message: "User with this email already exists",
      });
    } else {
      res.status(500).json({
        error: true,
        message: "Something went wrong",
      });
    }
  }
});
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (user) {
      let passwordMatch = await bcrypt.compare(password, user.password);
      if (passwordMatch) {
        const jwtToken = jwt.sign(user.toJSON(), process.env.JWT_SECRET, {
          expiresIn: "1h",
        });
        res.json({
          message: "success",
          data: "You have successfully logged in!",
          jwtToken,
        });
      } else {
        res.status(401).json({
          error: true,
          message: "Incorrect credentials. Please try again!",
        });
      }
    } else {
      res.status(401).json({
        error: true,
        message: "Incorrect credentials. Please try again!",
      });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({
      error: true,
      message: "Incorrect credentials. Please try again!",
    });
  }
});
app.listen(process.env.PORT, () => {
  mongoose
    .connect(process.env.MONGODB_URL, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    })
    .then(() =>
      console.log(`Connection was successful on port: ${process.env.PORT}`)
    )
    .catch((error) => console.log(error));
});

