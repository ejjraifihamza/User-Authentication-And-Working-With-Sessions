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
  let sessionInputData = req.session.inputData;
  if (!sessionInputData) {
    sessionInputData = {
      hasError: false,
      email: "",
      password: "",
    };
  }
  req.session.inputData = null; // will work in the next request
  res.render("login", { inputData: sessionInputData });
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
    req.session.inputData = {
      hasError: true,
      message: "Email Already Exist.",
      email: email,
      confirmEmail: confirmEmail,
      password: password,
    };
    req.session.save(() => {
      res.redirect("/signup");
    });
    return;
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
    req.session.inputData = {
      hasError: true,
      message: "Could not log you in - please check your credentials!",
      email: email,
      password: password,
    };
    req.session.save(() => {
      res.redirect("/login");
    });
    return;
  }
  const validPassword = await bcrypt.compare(password, existingUser.password);
  if (!validPassword) {
    req.session.inputData = {
      hasError: true,
      message: "Could not log you in - please check your credentials!",
      email: email,
      password: password,
    };
    req.session.save(() => {
      res.redirect("/login");
    });
    return;
  }
  // automaticaly and with help of express-session package below data will store in tha database
  req.session.user = { id: existingUser._id, email: existingUser.email };
  req.session.isAuthenticated = true;
  // to make sur that session insert to database before redirect to protected route(/admin)
  req.session.save(() => {
    res.redirect("/profile");
  });
});

router.get("/admin", async function (req, res) {
  if (!res.locals.isAuth) {
    // if (!req.session.isAuthenticated)
    // if (!req.session.user)
    return res.status(401).render("401");
  }

  if (!res.locals.isAdmin) {
    // if (!user || !user.isAdmin)
    return res.status(403).render("403");
  }

  res.render("admin");
});

router.get("/profile", function (req, res) {
  if (!res.locals.isAuth) {
    // if (!req.session.isAuthenticated)
    // if (!req.session.user)
    return res.status(401).render("401");
  }
  res.render("profile");
});

router.post("/logout", function (req, res) {
  req.session.user = null;
  req.session.isAuthenticated = false;
  res.redirect("/");
});

module.exports = router;
