import "dotenv/config";
import express from "express";
import mysql from "mysql2/promise";
import cors from "cors";
import multer from "multer";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { v2 as cloudinary } from "cloudinary";
import { CloudinaryStorage } from "multer-storage-cloudinary";
import fs from "fs";

const app = express();
const saltRounds = 10;
const PORT = process.env.PORT || 8000;

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT,
  ssl: {
    ca: fs.readFileSync("./certs/ca.pem"),
    rejectUnauthorized: true,
  },
});

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({ error: "Access denied. No token." });
  }

  const token = authHeader.split(" ")[1];

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    req.user = decoded;

    next();
  } catch (error) {
    return res.status(403).json({ error: "Invalid or expired token." });
  }
};

const allowedOrigins = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(",")
  : ["http://localhost:5173"];

app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error("Not allowed by CORS"));
      }
    },
    credentials: true,
  }),
);

app.use(express.json());

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

const storage = new CloudinaryStorage({
  cloudinary,
  params: {
    folder: "avatars",
    allowed_formats: ["jpg", "png", "jpeg"],
  },
});

const upload = multer({ storage });

app.get("/", async (req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT
        posts.*,
        users.first_name,
        users.last_name,
        users.email,
        users.avatar,
        COUNT(up_votes.upvote_id) AS upvotes
      FROM posts
      JOIN users
        ON posts.user_id = users.user_id
      LEFT JOIN up_votes
        ON posts.question_id = up_votes.question_id
      GROUP BY posts.question_id
      ORDER BY posts.date_posted DESC
      LIMIT 15
    `);

    const posts = rows.map((post) => ({
      ...post,
      date_posted: new Date(post.date_posted).toISOString().split("T")[0],
    }));

    res.json(posts);
  } catch (error) {
    console.log(error);

    res.status(500).json({
      error: "Database error",
    });
  }
});

app.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    const [result] = await pool.execute(
      `SELECT user_id,email,password,first_name FROM users WHERE email=?  `,
      [username],
    );
    // Check for the user
    if (result.length === 0) {
      return res.status(401).json({ error: "User not Found." });
    }
    //
    const user = result[0];
    const passCheck = await bcrypt.compare(password, user.password);

    if (!passCheck) {
      return res.status(401).json({ error: "User not Found." });
    }
    const token = jwt.sign(
      { userId: user.user_id, firstName: user.first_name },
      process.env.JWT_SECRET,
      {
        expiresIn: "1h",
      },
    );
    res.status(200).json({
      token: token,
      user: { id: user.user_id, firstName: user.first_name },
    });
  } catch (error) {
    res.status(500).json({
      error: "Database error",
    });
  }
});

app.post("/signup", upload.single("profilePicture"), async (req, res) => {
  try {
    const { firstName, lastName, email, password, birthdate } = req.body;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    if (!req.file) {
      return res.status(400).json({
        error: "Profile picture is required",
      });
    }

    const avatar = req.file.path;

    const [result] = await pool.execute(
      `
        INSERT INTO users
        (
          first_name,
          last_name,
          email,
          password,
          birthdate,
          avatar
        )
        VALUES (?, ?, ?, ?, ?, ?)
        `,
      [firstName, lastName, email, hashedPassword, birthdate, avatar],
    );

    res.status(201).json({
      message: "User created successfully",
      userId: result.insertId,
      avatar: avatar,
    });
  } catch (error) {
    console.log(error);

    res.status(500).json({
      error: "Signup failed",
    });
  }
});
app.post("/createpost", authenticateToken, async (req, res) => {
  try {
    const { question } = req.body;
    const userId = req.user.userId;
    const [result] = await pool.execute(
      `
      INSERT INTO posts
      (
        user_id,
        question_text
      )
      VALUES (?, ?)
      `,
      [userId, question],
    );

    res.status(201).json({
      message: "Post added successfully",
      questionId: result.insertId,
    });
  } catch (error) {
    console.log(error);
    res.status(500).json({
      error: "Posting question failed",
    });
  }
});

app.post("/question/:id/answered", authenticateToken, async (req, res) => {
  const questionId = req.params.id;
  const userId = req.user.userId;

  try {
    const [result] = await pool.execute(
      `UPDATE posts
       SET answered = 1
       WHERE question_id = ? AND user_id = ?`,
      [questionId, userId],
    );

    if (result.affectedRows === 0) {
      return res.status(403).json({
        message: "You cannot mark this question as answered.",
      });
    }

    res.json({
      message: "Question marked as answered",
    });
  } catch (error) {
    console.log(error);

    res.status(500).json({
      message: "Database error",
    });
  }
});

app.post("/question/:id/liked", authenticateToken, async (req, res) => {
  const questionId = req.params.id;
  const userId = req.user.userId;

  try {
    const [check] = await pool.execute(
      `SELECT user_id, question_id 
       FROM up_votes 
       WHERE user_id = ? AND question_id = ?`,
      [userId, questionId],
    );

    let message;

    if (check.length === 0) {
      await pool.execute(
        `INSERT INTO up_votes (question_id, user_id)
         VALUES (?, ?)`,
        [questionId, userId],
      );
      message = "Question liked";
    } else {
      await pool.execute(
        `DELETE FROM up_votes
         WHERE user_id = ? AND question_id = ?`,
        [userId, questionId],
      );
      message = "Question unliked";
    }

    const [result] = await pool.query(
      `SELECT COUNT(up_votes.upvote_id) AS upvotes
       FROM up_votes
       WHERE up_votes.question_id = ?`,
      [questionId],
    );

    res.status(200).json({
      message,
      upvotes: result[0].upvotes,
    });
  } catch (error) {
    console.log(error);

    res.status(500).json({
      message: "Like failed",
    });
  }
});

app.listen(PORT, () => {
  console.log(`The server is running on ${PORT}`);
});
