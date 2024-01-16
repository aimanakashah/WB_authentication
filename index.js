import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt, { hash } from "bcrypt";
import session from "express-session";
import passport from "passport";
import { Strategy } from "passport-local";

const app = express();
const port = 3000;
const saltRounds = 10;

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(
  session({
    secret: "TOPSECRETWORD",
    resave: false,
    saveUninitialized: true,
    //to set the time of the sesion using miliseconds, 1000 = 1s
    cookie: {
      maxAge: 1000 * 60 * 60,
    },
  })
);

app.use(passport.initialize());
app.use(passport.session());

const db = new pg.Client({
  user: "postgres",
  host: "localhost",
  database: "Authentication",
  password: "1234567890",
  port: 5432,
});
db.connect();

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/secrets", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("secrets.ejs");
  } else {
    res.redirect("/login");
  }
});
app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  try {
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);
    //using the length is because the the data is already extracted from database. if no data extracted meaning the length is 0 thus the email does not exist yet
    if (checkResult.rows.length > 0) {
      res.send("Email already exists, try logging in.");
    } else {
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.log("Error hashing password", err);
        } else {
          const result = await db.query(
            "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *;",
            [email, hash]
          );
          const user = result.rows[0];
          //this authenticates the user by passing the information to the serialize and deserialize
          req.login(user, (err) => {
            console.log(err);
            res.redirect("/register");
          });
        }
      });
    }
  } catch (err) {
    console.log(err);
  }
});

app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);

passport.use(
  new Strategy(async function verify(username, password, cb) {
    //the 'verify' function get the data like 'username' and 'password' straight from ejs name as long as it is the same, thus no need to extract it like using bodyParser
    try {
      const checkResult = await db.query(
        "SELECT * FROM users WHERE email = $1;",
        [username]
      );
      //if 'email' is found, the length of the rows will always be 1. More than 1 indicates two same 'email' registered which is wrong since the 'email' is set as UNIQUE in the database
      if (checkResult.rows.length > 0) {
        const user = checkResult.rows[0];
        const storedPassword = user.password;

        bcrypt.compare(password, storedPassword, (err, result) => {
          // result == true, already compared when using this bcrypt method, so just put the result.
          if (err) {
            return cb(err);
          } else {
            if (result) {
              return cb(null, user); //this will pass as null since there is no error since the result is true, and the 'user' as true.
            } else {
              return cb(null, false); //this will set the authenticated to false
            }
          }
          // res.render("secrets.ejs");
        });
      } else {
        return cb("User not found");
      }
    } catch (err) {
      return cb(err);
    }
  })
);

//the function called when a user is authenticated, its purpose is to determine which data of the user object should be stored in the session
passport.serializeUser((user, cb) => {
  //using cb to over any of the user detail to the database
  cb(null, user);
});

//the function is called when a user makes a request, it is to retrieve the user information from the session
passport.deserializeUser((user, cb) => {
  cb(null, user);
});

app.listen(port, () => {
  console.log(`The server is now running on http://localhost:${port}`);
});
