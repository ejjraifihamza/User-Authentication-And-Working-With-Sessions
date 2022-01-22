const express = require("express");
const bcrypt = require("bcryptjs");

const db = require("../data/database");

const router = express.Router();

router.get("/", function (req, res) {
  res.render("welcome");
});

router.get("/signup", function (req, res) {
  res.render("signup");
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
    return res.status(500).json({ error: "Invalid Data!" });
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
  res.redirect("/admin");
});

router.get("/admin", function (req, res) {
  res.render("admin");
});

router.post("/logout", function (req, res) {});

module.exports = router;
