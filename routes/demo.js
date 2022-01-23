const express = require("express");
const bcrypt = require("bcryptjs");

const db = require("../data/database");

const router = express.Router();

router.get("/", function (req, res) {
  res.render("welcome");
});

router.get("/signup", function (req, res) {
  let sessionInputData = req.session.inputData;
  if (!sessionInputData) {
    sessionInputData = {
      hasError: false,
      email: "",
      confirmEmail: "",
      password: "",
    };
  }
  req.session.inputData = null; // will work in the next request
  res.render("signup", { inputData: sessionInputData });
});

router.get("/login", function (req, res) {
  res.render("login");
});

router.post("/signup", async function (req, res) {
  const userData = req.body;
  const confirmEmail = userData["confirm-email"];
  const { email, password } = userData;

  if (
    !email ||
    !confirmEmail ||
    !password ||
    password.trim().length < 6 ||
    email !== confirmEmail ||
    !email.includes("@")
  ) {
    req.session.inputData = {
      hasError: true,
      message: "Invalid input - please check your data.",
      email: email,
      confirmEmail: confirmEmail,
      password: password,
    };
    req.session.save(() => {
      res.redirect("/signup");
    });
    return;
  }

  const existingUser = await db
    .getDb()
    .collection("users")
    .findOne({ email: email });
  if (existingUser) {
    return res.status(500).json({ error: "Email Already Existing!" });
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  await db.getDb().collection("users").insertOne({
    email: email,
    password: hashedPassword,
  });
  res.redirect("/login");
});

router.post("/login", async function (req, res) {
  const { email, password } = req.body;
  const existingUser = await db
    .getDb()
    .collection("users")
    .findOne({ email: email });
  if (!existingUser) {
    res.status(500).json({ message: "Incorrect Email" });
    return;
  }
  const validPassword = await bcrypt.compare(password, existingUser.password);
  if (!validPassword) {
    res.status(500).json({ message: "Incorrect Password" });
    return;
  }
  // automaticaly and with help of express-session package below data will store in tha database
  req.session.user = { id: existingUser._id, email: existingUser.email };
  req.session.isAuthenticated = true;
  // to make sur that session insert to database before redirect to protected route(/admin)
  req.session.save(() => {
    res.redirect("/admin");
  });
});

router.get("/admin", function (req, res) {
  if (!req.session.isAuthenticated) {
    // if (!req.session.user)
    return res.status(401).render("401");
  }
  res.render("admin");
});

router.post("/logout", function (req, res) {
  req.session.user = null;
  req.session.isAuthenticated = false;
  res.redirect("/");
});

module.exports = router;
