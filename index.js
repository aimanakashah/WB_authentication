import express from "express";
import bodyParser from "body-parser";
import pg from "pg";

const app = express();
const port = 3000;

const db = new pg.Client({
  user: "postgres",
  host: "localhost",
  database: "Authentication",
  password: "1234567890",
  port: 5432,
});
db.connect();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
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
      const result = await db.query(
        "INSERT INTO users (email, password) VALUES ($1, $2);",
        [email, password]
      );
      console.log(result);
      res.render("secrets.ejs");
    }
  } catch (err) {
    console.log(err);
  }
});

app.post("/login", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  try {
    const checkResult = await db.query(
      "SELECT * FROM users WHERE email = $1;",
      [email]
    );
    //if 'email' is found, the length of the rows will always be 1. More than 1 indicates two same 'email' registered which is wrong since the 'email' is set as UNIQUE in the database
    if (checkResult.rows.length > 0) {
      const user = checkResult.rows[0];
      const storedPassword = user.password;

      if (storedPassword === password) {
        res.render("secrets.ejs");
      } else {
        res.send("Wrong password, try again.");
      }
    } else {
      res.send("No email registered. Try register an account.");
    }
  } catch (err) {
    console.log(err);
  }
});

app.listen(port, () => {
  console.log(`The server is now running on http://localhost:${port}`);
});
