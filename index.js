require("dotenv/config");
const express = require("express");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const { verify } = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const { fakeDB } = require("./fakeDB");
const {
  createAccessToken,
  createRefreshToken,
  sendAccessToken,
  sendRefreshToken,
} = require("./tokens");
const { isAuth } = require("./isAuth");
const { accessToken } = require("mapbox-gl");
//1. Register a user
//2. login a user
//3. logout a user
//4. setup a protected route
//5. get a new accesstoken with a refresh token

const app = express();

//use express middleware
app.use(cookieParser());

app.use(
  cors({
    origin: "http://localhost:4000",
    credentials: true,
  })
);

app.use(express.json()); // to support Json encoded data
app.use(express.urlencoded({ extended: true }));

// app.get("/", (req, res) => {
//   res.send("hi");
// });

//1.Register a User

app.post("/register", async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = fakeDB.find((user) => user.email === email);
    if (user) {
      //if user exist throw error
      return res.status(400).json({ error: "User Already Exist" });
    } //else hash the password
    // Check if password exists before hashing
    if (!password) {
      return res.status(400).json({ error: "Password is required" });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    console.log(hashedPassword);
    fakeDB.push({
      id: fakeDB.length,
      email,
      password: hashedPassword,
    });
    console.log(fakeDB);
    return res.status(201).json({
      message: "User created successfully",
    });
  } catch (err) {
    console.log(err);
    return res.status(500).json({
      error: "Error creating user",
    });
  }
});

//2. Login a User

app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    //1. find user in DB
    const user = fakeDB.find((user) => user.email === email);
    if (!user) {
      return res.status(400).json({
        error: "User does not exist",
      });
    }

    //2. Compare crypted password ans see if it checks out . Send error if not
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) {
      return res.status(400).json({
        message: "wrong credentials",
      });
    }

    //3. Create refresh token and access token
    const accesstoken = createAccessToken(user.id);
    const refreshtoken = createRefreshToken(user.id);

    //4. put the refreshtoken in the database
    user.refreshtoken = refreshtoken;
    console.log(fakeDB);

    //5. send token. refreshtoken as a cookie and accesstoken as a regular response
    sendRefreshToken(res, refreshtoken);
    sendAccessToken(req, res, accesstoken);
  } catch (e) {
    console.log(e);
    return res.status(500).json({
      error: "error to login",
    });
  }
});

//3. logout a user

app.post("/logout", async (req, res) => {
  res.clearCookie("refreshtoken", { path: "/refresh_token" });
  return res.send({
    message: "logged out",
  });
});

//4. Protected Route
app.post("/protected", isAuth, (req, res) => {
  try {
    const userId = req.userId; // Access userId from req object
    if (userId !== null) {
      res.send({
        data: "This is protected data",
      });
    }
  } catch (e) {
    res.send({
      err: `${e.message}`,
    });
  }
});

//5. Get a new access token with a refresh token
app.post("/refresh_token", (req, res) => {
  const token = req.cookies.refreshtoken;
  //if we dont have token in our request
  if (!token) {
    return res.send({ accesstoken: "" });
  }
  let payload = null;
  try {
    payload = verify(token, process.env.REFRESH_TOKEN_SECRET);
  } catch (e) {
    return res.send({ accessToken: "" });
  }
  //token is valid , check if user exist
  const user = fakeDB.find((user) => user.id === payload.userId);
  if (!user) {
    return res.send({ accesstoken: "" });
  }
  //user exist, check if refreshtoken exist on user
  if (user.refreshtoken !== token) {
    return res.send({ accesstoken: "" });
  }
  //token exist , create new refresh and access token
  const accesstoken = createAccessToken(user.id);
  const refreshtoken = createRefreshToken(user.id);
  user.refreshtoken = refreshtoken;

  //all goooood, send new refresh and access token
  sendRefreshToken(res, refreshtoken);
  return res.send({ accesstoken });
});

app.listen(process.env.PORT, () => {
  console.log(`server listening on port ${process.env.PORT}`);
});
