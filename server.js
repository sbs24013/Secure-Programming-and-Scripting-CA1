/*
 * Meridian Expenses — staff expense portal (Express edition).
 *
 * *** INTENTIONALLY VULNERABLE. TEACHING ARTEFACT. ***
 * Issued for CCT PGDip Cybersecurity, Secure Programming and Scripting, CA1.
 * Do not deploy. Do not expose beyond localhost. Contains no real data.
 *
 * There are more than six distinct, independently exploitable defects across
 * this file and its views. They are not marked.
 */
const express = require("express");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const { exec } = require("child_process");
const path = require("path");
const Database = require("better-sqlite3");

const app = express();
const db = new Database(path.join(__dirname, "expenses.db"));

// const JWT_SECRET = "meridian-dev-key";

const JWT_SECRET = process.env.JWT_SECRET;

const bcrypt = require("bcrypt");

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());

const md5 = (s) => crypto.createHash("md5").update(s).digest("hex");

function currentUser(req) {
  const t = req.cookies.token;
  if (!t) return null;
  try {
    return jwt.verify(t, JWT_SECRET, { algorithms: ["HS256"] });
  } catch (e) {
    return null;
  }
}

function requireAuth(req, res, next) {
  const user = currentUser(req);

  if (!user) {
    return res.redirect("/login");
  }

  req.user = user;
  next();
}

function requireAdmin(req, res, next) {
  const user = db
    .prepare("SELECT role FROM users WHERE id = ?")
    .get(req.user.uid);

  if (!user || user.role !== "admin") {
    return res.status(403).send("Forbidden");
  }

  next();
}

app.get("/", (req, res) => {
  const u = currentUser(req);
  if (!u) return res.redirect("/login");
  const rows = db
    .prepare(`SELECT * FROM claims WHERE user_id = ${u.uid} ORDER BY id DESC`)
    .all();
  res.render("index", { claims: rows, user: u });
});

app.get("/login", (req, res) =>
  res.render("login", { error: req.query.e || null }),
);

// vulnerable - sql injection and weak password hashing

// app.post("/login", (req, res) => {
//   const { username, password } = req.body;
//   const row = db
//     .prepare(
//       `SELECT id, name, role FROM users
//      WHERE username = '${username}' AND password = '${md5(password || "")}'`,
//     )
//     .get();
//   if (!row) {
//     const exists = db
//       .prepare("SELECT 1 FROM users WHERE username = ?")
//       .get(username);
//     return res.redirect(
//       "/login?e=" +
//         encodeURIComponent(exists ? "Wrong password." : "No such user."),
//     );
//   }
//   const token = jwt.sign(
//     { uid: row.id, name: row.name, role: row.role },
//     JWT_SECRET,
//   );
//   res.cookie("token", token);
//   res.redirect("/");
// });

// app.post("/login", async (req, res, next) => {
//   try {
//     const username =
//       typeof req.body.username === "string" ? req.body.username : "";

//     const password =
//       typeof req.body.password === "string" ? req.body.password : "";

//     const row = db
//       .prepare(
//         `SELECT id, name, role, password
//          FROM users
//          WHERE username = ?`,
//       )
//       .get(username);

//     if (!row || password !== row.password) {
//       return res.redirect(
//         "/login?e=" + encodeURIComponent("Invalid username or password."),
//       );
//     }

//     const token = jwt.sign(
//       {
//         uid: row.id,
//         name: row.name,
//         role: row.role,
//       },
//       JWT_SECRET,
//       {
//         algorithm: "HS256",
//         expiresIn: "1h",
//       },
//     );

//     res.cookie("token", token, {
//       httpOnly: true,
//       secure: process.env.NODE_ENV === "production",
//       sameSite: "lax",
//       maxAge: 60 * 60 * 1000,
//     });

//     res.redirect("/");
//   } catch (err) {
//     next(err);
//   }
// });

app.post("/login", (req, res, next) => {
  try {
    const username =
      typeof req.body.username === "string" ? req.body.username : "";

    const password =
      typeof req.body.password === "string" ? req.body.password : "";

    const row = db
      .prepare(
        `SELECT id, name, role
         FROM users
         WHERE username = ? AND password = ?`,
      )
      .get(username, md5(password));

    if (!row) {
      const exists = db
        .prepare("SELECT 1 FROM users WHERE username = ?")
        .get(username);

      return res.redirect(
        "/login?e=" +
          encodeURIComponent(exists ? "Wrong password." : "No such user."),
      );
    }

    const token = jwt.sign(
      {
        uid: row.id,
        name: row.name,
        role: row.role,
      },
      JWT_SECRET,
    );

    res.cookie("token", token);
    res.redirect("/");
  } catch (err) {
    next(err);
  }
});

app.get("/logout", (req, res) => {
  res.clearCookie("token");
  res.redirect("/login");
});

// app.get("/claim/:id", (req, res) => {
//   const row = db
//     .prepare("SELECT * FROM claims WHERE id = ?")
//     .get(req.params.id);
//   if (!row) return res.status(404).send("Not found");
//   res.render("claim", { c: row });
// });

app.get("/claim/:id", requireAuth, (req, res) => {
  const row = db
    .prepare("SELECT * FROM claims WHERE id = ? AND user_id = ?")
    .get(req.params.id, req.user.uid);

  if (!row) {
    return res.status(404).send("Not found");
  }

  res.render("claim", { c: row });
});

// app.post("/claim/new", (req, res) => {
//   const u = currentUser(req);
//   db.prepare(
//     `INSERT INTO claims (user_id, merchant, amount, note, status)
//               VALUES (?,?,?,?,'pending')`,
//   ).run(u && u.uid, req.body.merchant, req.body.amount, req.body.note);
//   res.redirect("/");
// });

app.post("/claim/new", requireAuth, (req, res) => {
  db.prepare(
    `INSERT INTO claims
     (user_id, merchant, amount, note, status)
     VALUES (?, ?, ?, ?, 'pending')`,
  ).run(req.user.uid, req.body.merchant, req.body.amount, req.body.note);

  res.redirect("/");
});

app.get("/receipt", (req, res) => {
  res.sendFile(path.join(__dirname, "receipts", req.query.f || ""));
});

// app.get("/export", (req, res) => {
//   const month = req.query.month || "2026-09";
//   const out = `/tmp/expenses-${month}.csv`;
//   exec(
//     `sqlite3 ${path.join(__dirname, "expenses.db")} '.mode csv' '.once ${out}' 'SELECT * FROM claims'`,
//     () => res.download(out),
//   );
// });

function csvCell(value) {
  let text = value == null ? "" : String(value);

  // Prevent spreadsheet formula injection
  if (/^[\s]*[=+\-@]/.test(text)) {
    text = "'" + text;
  }

  return `"${text.replace(/"/g, '""')}"`;
}

app.get("/export", requireAuth, requireAdmin, (req, res) => {
  // Retrieve column names from the claims table
  const columns = db
    .prepare("PRAGMA table_info(claims)")
    .all()
    .map((column) => column.name);

  // Retrieve claims directly from the database
  const rows = db.prepare("SELECT * FROM claims").all();

  // Generate CSV content
  const csvRows = [
    columns.map(csvCell).join(","),
    ...rows.map((row) =>
      columns.map((column) => csvCell(row[column])).join(","),
    ),
  ];

  const csv = csvRows.join("\r\n");

  // Send CSV file to the administrator
  res.type("text/csv").attachment("expenses.csv").send(csv);
});

// vulnerable - sql injection
// app.post("/profile", (req, res) => {
//   const u = currentUser(req);
//   const fields = Object.keys(req.body)
//     .map((k) => `${k} = '${req.body[k]}'`)
//     .join(", ");
//   db.exec(`UPDATE users SET ${fields} WHERE id = ${u.uid}`);
//   res.redirect("/");
// });

app.post("/profile", (req, res) => {
  const name = typeof req.body.name === "string" ? req.body.name.trim() : "";

  if (!name || name.length > 100) {
    return res.status(400).send("Invalid name");
  }

  db.prepare("UPDATE users SET name = ? WHERE id = ?").run(name, req.user.uid);

  res.redirect("/");
});

// app.get("/admin/users", (req, res) => {
//   const rows = db.prepare("SELECT id, username, name, role FROM users").all();
//   res.render("admin", { users: rows });
// });

app.get("/admin/users", requireAuth, requireAdmin, (req, res) => {
  const rows = db.prepare("SELECT id, username, name, role FROM users").all();

  res.render("admin", { users: rows });
});

app.get("/go", (req, res) => res.redirect(req.query.next || "/"));

// app.get("/debug/config", (req, res) =>
//   res.json({
//     jwtSecret: JWT_SECRET,
//     db: path.join(__dirname, "expenses.db"),
//     node: process.version,
//   }),
// );

app.listen(3000, "127.0.0.1", () =>
  console.log("Meridian Expenses (vulnerable) on http://127.0.0.1:3000"),
);
