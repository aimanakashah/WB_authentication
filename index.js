import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt, { hash } from "bcrypt";
import session from "express-session";
import passport from "passport";
import { Strategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth2";
import env from "dotenv";

const app = express();
const port = 3000;
const saltRounds = 10;
env.config();

app.use(
  session({
    secret: process.env.SESSION_KEY,
    resave: false,
    saveUninitialized: true,
    //to set the time of the sesion using miliseconds, 1000 = 1s
    cookie: {
      maxAge: 1000 * 60 * 60,
    },
  })
);
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(passport.initialize());
app.use(passport.session());

const db = new pg.Client({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_DATABASE,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
});
db.connect();

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/logout", (req, res) => {
  req.logout((err) => {
    if (err) {
      console.error(err);
    } else {
      res.redirect("/");
    }
  });
});

app.get("/secrets", async (req, res) => {
  //true
  if (req.isAuthenticated()) {
    const email = req.user.email; //passport authentication from cb
    const result = await db.query("SELECT * from users WHERE email = $1", [
      email,
    ]);
    const secret = result.rows[0].secrets;
    if (secret) {
      res.render("secrets.ejs", {
        secret: secret,
      });
    } else {
      res.redirect("/submit");
    }
  } else {
    res.redirect("/login");
  }
});

app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
  })
);

app.get(
  "/auth/google/secrets",
  passport.authenticate("google", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);

app.get("/logout", (req, res) => {
  req.logout((err) => {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

app.get("/submit", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("submit.ejs");
  } else {
    res.redirect("/login");
  }
});

app.post("/submit", async (req, res) => {
  const newSecret = req.body.secret;

  try {
    await db.query(
      "UPDATE users SET secrets = $1 WHERE email = $2",
      [newSecret, req.user.email]
      //using passport cb method to get the user req.user
    );
    res.redirect("/secrets");
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

app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  try {
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);
    //using the length is because the the data is already extracted from database. if no data extracted meaning the length is 0 thus the email does not exist yet
    if (checkResult.rows.length > 0) {
      req.redirect("/login");
      // res.send("Email already exists, try logging in.");
    } else {
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error("Error hashing password", err);
        } else {
          const result = await db.query(
            "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *;",
            [email, hash]
          );
          const user = result.rows[0];
          //this req.login authenticates the user by passing the information to the serialize and deserialize method
          req.login(user, (err) => {
            console.log(err);
            res.redirect("/submit");
            // res.redirect("/register");
          });
        }
      });
    }
  } catch (err) {
    console.log(err);
  }
});

passport.use(
  "local",
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
        // res.redirect("/register");
        return cb("User not found");
      }
    } catch (err) {
      return cb(err);
    }
  })
);

passport.use(
  "google",
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/secrets",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    async (accessToken, refreshToken, profile, cb) => {
      // console.log(profile);
      try {
        const result = await db.query("SELECT * FROM users WHERE email = $1", [
          profile.email,
        ]);

        if (result.rows.length === 0) {
          const newUser = await db.query(
            "INSERT INTO users (email, password) VALUES ($1, $2)",
            [profile.email, "google"]
          );
          return cb(null, newUser.rows[0]);
        } else {
          //Already have user, passing result since it is in different part of if else
          return cb(null, result.rows[0]);
        }
      } catch (err) {
        cb(err);
      }
    }
  )
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
