const express = require("express");
const bycrypt = require("bcryptjs");

const db = require("../data/database");
const bcrypt = require("bcryptjs/dist/bcrypt");

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
  const hashedPassword = await bcrypt.hash(password, 10);

  await db.getDb().collection("users").insertOne({
    email: email,
    password: hashedPassword,
  });
  res.redirect("/login");
});

router.post("/login", async function (req, res) {});

router.get("/admin", function (req, res) {
  res.render("admin");
});

router.post("/logout", function (req, res) {});

module.exports = router;
