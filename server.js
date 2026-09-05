import express from "express";
import jwt from "jsonwebtoken";
import cors from "cors";
import bcrypt from "bcrypt";
import crypto from "crypto";
import multer from "multer";
import path from "path";
import fs from "fs";
import { fileTypeFromFile } from "file-type";

import db from "./database.js";

// ============================================================
// CONFIG
// ============================================================

const app = express();

const PORT = 3000;
const PW = "https://www.pw.live";

const allowedOrigins = [
  `https://kitnapadhabackend-production.up.railway.app`,
  PW,
];

// ------------------------------------------------------------
// JWT SECRET
// ------------------------------------------------------------

const JWT_SECRET =
  process.env.JWT_SECRET || "dev-only-secret-change-before-deployment";

if (process.env.NODE_ENV === "production" && !process.env.JWT_SECRET) {
  console.error(
    "FATAL: JWT_SECRET environment variable is required in production.",
  );

  process.exit(1);
}

// ============================================================
// MIDDLEWARE
// ============================================================

app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin) {
        return callback(null, true);
      }

      if (origin.startsWith("chrome-extension://")) {
        return callback(null, true);
      }

      if (allowedOrigins.includes(origin)) {
        return callback(null, true);
      }

      return callback(new Error("Not allowed by CORS"));
    },
  }),
);

app.use(express.json());

// ============================================================
// HELPERS
// ============================================================

function normalizeUsername(username) {
  return String(username || "")
    .trim()
    .toLowerCase();
}

function createToken(user) {
  return jwt.sign(
    {
      userId: user.id,
      kitnaId: user.kitna_id,
    },

    JWT_SECRET,

    {
      expiresIn: "7d",
    },
  );
}

function validateUsername(username) {
  if (!username) {
    return "Username is required.";
  }

  if (username.length < 3) {
    return "Username must be at least 3 characters.";
  }

  if (username.length > 24) {
    return "Username must be 24 characters or fewer.";
  }

  if (!/^[a-z0-9_]+$/.test(username)) {
    return "Username can only contain lowercase letters, numbers and underscores.";
  }

  return null;
}

function validateDisplayName(displayName) {
  if (!displayName) {
    return "Display name is required.";
  }

  if (displayName.length > 40) {
    return "Display name must be 40 characters or fewer.";
  }

  return null;
}

// ============================================================
// AUTHENTICATION MIDDLEWARE
// ============================================================

function authenticateToken(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({
      error: "No valid token provided",
    });
  }

  const token = authHeader.slice(7);

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    req.user = decoded;

    next();
  } catch (error) {
    return res.status(401).json({
      error: "Invalid or expired token",
    });
  }
}

// ============================================================
// CREATE ACCOUNT
// ============================================================

app.post("/users", async (req, res) => {
  try {
    const displayName = String(req.body?.displayName || "").trim();

    const username = normalizeUsername(req.body?.username);

    const password = String(req.body?.password || "");

    // --------------------------------------------------------
    // Validate display name
    // --------------------------------------------------------

    const displayNameError = validateDisplayName(displayName);

    if (displayNameError) {
      return res.status(400).json({
        error: displayNameError,
      });
    }

    // --------------------------------------------------------
    // Validate username
    // --------------------------------------------------------

    const usernameError = validateUsername(username);

    if (usernameError) {
      return res.status(400).json({
        error: usernameError,
      });
    }

    // --------------------------------------------------------
    // Validate password
    // --------------------------------------------------------

    if (!password) {
      return res.status(400).json({
        error: "Password is required.",
      });
    }

    if (password.length < 8) {
      return res.status(400).json({
        error: "Password must be at least 8 characters.",
      });
    }

    // --------------------------------------------------------
    // Check username before hashing
    // --------------------------------------------------------

    const existingUser = db
      .prepare(
        `
        SELECT id
        FROM users
        WHERE username = ?
        LIMIT 1
        `,
      )
      .get(username);

    if (existingUser) {
      return res.status(409).json({
        error: "Username already exists.",
      });
    }

    // --------------------------------------------------------
    // Generate Kitna ID
    // --------------------------------------------------------

    const kitnaId = `KP-${crypto.randomBytes(4).toString("hex").toUpperCase()}`;

    // --------------------------------------------------------
    // Hash password
    // --------------------------------------------------------

    const passwordHash = await bcrypt.hash(password, 10);

    // --------------------------------------------------------
    // Create account
    // --------------------------------------------------------

    const statement = db.prepare(
      `
      INSERT INTO users
      (
        kitna_id,
        username,
        display_name,
        password_hash,
        created_at
      )
      VALUES (?, ?, ?, ?, ?)
      `,
    );

    const result = statement.run(
      kitnaId,
      username,
      displayName,
      passwordHash,
      new Date().toISOString(),
    );

    // --------------------------------------------------------
    // Fetch newly created user
    // --------------------------------------------------------

    const user = db
      .prepare(
        `
        SELECT
          id,
          kitna_id
        FROM users
        WHERE id = ?
        `,
      )
      .get(result.lastInsertRowid);

    if (!user) {
      return res.status(500).json({
        error: "Account was created but could not be loaded.",
      });
    }

    // --------------------------------------------------------
    // Create JWT
    // --------------------------------------------------------

    const token = createToken(user);

    // --------------------------------------------------------
    // Response
    // --------------------------------------------------------

    return res.status(201).json({
      message: "Account created successfully",
      kitnaId: user.kitna_id,
      token,
    });
  } catch (error) {
    console.error("CREATE ACCOUNT ERROR:", error);

    if (error.code === "SQLITE_CONSTRAINT_UNIQUE") {
      return res.status(409).json({
        error: "Username already exists.",
      });
    }

    return res.status(500).json({
      error: "Something went wrong while creating your account.",
    });
  }
});

// ============================================================
// LOGIN
// ============================================================

app.post("/auth/login", async (req, res) => {
  try {
    const username = normalizeUsername(req.body?.username);

    const password = String(req.body?.password || "");

    if (!username || !password) {
      return res.status(400).json({
        error: "Username and password are required.",
      });
    }

    const user = db
      .prepare(
        `
        SELECT *
        FROM users
        WHERE username = ?
        LIMIT 1
        `,
      )
      .get(username);

    // IMPORTANT:
    // Don't tell the user whether the username
    // or password specifically was wrong.
    if (!user) {
      return res.status(401).json({
        error: "Invalid username or password.",
      });
    }

    const passwordMatches = await bcrypt.compare(password, user.password_hash);

    if (!passwordMatches) {
      return res.status(401).json({
        error: "Invalid username or password.",
      });
    }

    const token = createToken(user);

    return res.json({
      message: "Login successful",
      token,
      kitnaId: user.kitna_id,
    });
  } catch (error) {
    console.error("LOGIN ERROR:", error);

    return res.status(500).json({
      error: "Something went wrong while logging in.",
    });
  }
});

// ============================================================
// CURRENT USER
// ============================================================

app.get("/auth/me", authenticateToken, (req, res) => {
  res.json({
    kitnaId: req.user.kitnaId,
  });
});

// ============================================================
// GET USER
// ============================================================

app.get("/users/:kitnaId", authenticateToken, (req, res) => {
  const { kitnaId } = req.params;

  const user = db
    .prepare(
      `
        SELECT
          id,
          kitna_id,
          username,
          display_name,
          pfp,
          current_streak,
          highest_streak,
          weekly_xp,
          all_time_xp,
          thoughts,
          exams,
          targeting,
          created_at
        FROM users
        WHERE kitna_id = ?
        `,
    )
    .get(kitnaId);

  if (!user) {
    return res.status(404).json({
      error: "User not found",
    });
  }

  res.json(user);
});

// ============================================================
// FRIEND REQUEST
// ============================================================

app.post("/friend-requests", authenticateToken, (req, res) => {
  const { receiverKitnaId } = req.body;

  if (!receiverKitnaId) {
    return res.status(400).json({
      error: "Receiver ID is required",
    });
  }

  const sender = db
    .prepare(
      `
        SELECT id, kitna_id
        FROM users
        WHERE id = ?
        `,
    )
    .get(req.user.userId);

  const receiver = db
    .prepare(
      `
        SELECT id, kitna_id
        FROM users
        WHERE kitna_id = ?
        `,
    )
    .get(receiverKitnaId);

  if (!sender || !receiver) {
    return res.status(404).json({
      error: "User not found",
    });
  }

  if (sender.id === receiver.id) {
    return res.status(400).json({
      error: "You cannot add yourself",
    });
  }

  const existingRequest = db
    .prepare(
      `
        SELECT *
        FROM friend_requests
        WHERE
          (sender_id = ? AND receiver_id = ?)
          OR
          (sender_id = ? AND receiver_id = ?)
        `,
    )
    .get(sender.id, receiver.id, receiver.id, sender.id);

  if (existingRequest) {
    return res.status(409).json({
      error: "A friend request or friendship already exists",
    });
  }

  const result = db
    .prepare(
      `
        INSERT INTO friend_requests
        (
          sender_id,
          receiver_id,
          status,
          created_at
        )
        VALUES (?, ?, 'pending', ?)
        `,
    )
    .run(sender.id, receiver.id, new Date().toISOString());

  res.status(201).json({
    message: "Friend request sent",
    requestId: result.lastInsertRowid,
  });
});

// ============================================================
// FRIENDSHIP STATUS
// ============================================================

app.get(
  "/friend-requests/status/:senderKitnaId/:receiverKitnaId",
  authenticateToken,
  (req, res) => {
    const { senderKitnaId, receiverKitnaId } = req.params;

    const relationship = db
      .prepare(
        `
        SELECT
          fr.id,
          fr.status,
          sender.kitna_id AS sender_kitna_id,
          receiver.kitna_id AS receiver_kitna_id
        FROM friend_requests fr
        JOIN users sender
          ON sender.id = fr.sender_id
        JOIN users receiver
          ON receiver.id = fr.receiver_id
        WHERE
          (
            sender.kitna_id = ?
            AND receiver.kitna_id = ?
          )
          OR
          (
            sender.kitna_id = ?
            AND receiver.kitna_id = ?
          )
        LIMIT 1
        `,
      )
      .get(senderKitnaId, receiverKitnaId, receiverKitnaId, senderKitnaId);

    if (!relationship) {
      return res.json({
        status: "none",
      });
    }

    res.json({
      status: relationship.status,
      senderKitnaId: relationship.sender_kitna_id,
      receiverKitnaId: relationship.receiver_kitna_id,
    });
  },
);

// ============================================================
// PENDING FRIEND REQUESTS
// ============================================================

app.get("/friend-requests/:kitnaId", authenticateToken, (req, res) => {
  const requests = db
    .prepare(
      `
        SELECT
          fr.id,
          u.kitna_id,
          u.username,
          u.weekly_xp,
          u.pfp,
          u.display_name,
          fr.created_at
        FROM friend_requests fr
        JOIN users u
          ON u.id = fr.sender_id
        JOIN users receiver
          ON receiver.id = fr.receiver_id
        WHERE receiver.id = ?
          AND fr.status = 'pending'
        `,
    )
    .all(req.user.userId);

  res.json(requests);
});

// ============================================================
// ACCEPT FRIEND REQUEST
// ============================================================

app.post(
  "/friend-requests/:requestId/accept",
  authenticateToken,
  (req, res) => {
    const { requestId } = req.params;

    const request = db
      .prepare(
        `
        SELECT *
        FROM friend_requests
        WHERE id = ?
          AND receiver_id = ?
          AND status = 'pending'
        `,
      )
      .get(requestId, req.user.userId);

    if (!request) {
      return res.status(404).json({
        error: "Friend request not found",
      });
    }

    db.prepare(
      `
      UPDATE friend_requests
      SET status = 'accepted'
      WHERE id = ?
      `,
    ).run(requestId);

    res.json({
      message: "Friend request accepted",
    });
  },
);

// ============================================================
// REJECT FRIEND REQUEST
// ============================================================

app.delete("/friend-requests/:requestId", authenticateToken, (req, res) => {
  const { requestId } = req.params;

  const result = db
    .prepare(
      `
        DELETE FROM friend_requests
        WHERE id = ?
          AND receiver_id = ?
          AND status = 'pending'
        `,
    )
    .run(requestId, req.user.userId);

  if (result.changes === 0) {
    return res.status(404).json({
      error: "Friend request not found",
    });
  }

  res.json({
    message: "Friend request rejected",
  });
});

// ============================================================
// GET FRIENDS
// ============================================================

app.get("/friends/:kitnaId", authenticateToken, (req, res) => {
  try {
    const userId = req.user.userId;

    const friends = db
      .prepare(
        `
          SELECT
            u.id,
            u.kitna_id,
            u.username,
            u.weekly_xp,
            u.pfp,
            u.display_name
          FROM friend_requests fr
          JOIN users u
            ON u.id = CASE
              WHEN fr.sender_id = ?
                THEN fr.receiver_id
              ELSE fr.sender_id
            END
          WHERE
            (fr.sender_id = ?
              OR fr.receiver_id = ?)
            AND fr.status = 'accepted'
          `,
      )
      .all(userId, userId, userId);

    res.json(friends);
  } catch (error) {
    console.error("GET FRIENDS ERROR:", error);

    res.status(500).json({
      error: "Failed to load friends.",
    });
  }
});

// ============================================================
// UPDATE PROFILE
// ============================================================

app.patch("/users/:kitnaId/profile", authenticateToken, (req, res) => {
  try {
    const userId = req.user.userId;

    const { thoughts, exams, targeting, display_name } = req.body;

    const result = db
      .prepare(
        `
          UPDATE users
          SET
            thoughts = ?,
            exams = ?,
            targeting = ?,
            display_name = ?
          WHERE id = ?
          `,
      )
      .run(thoughts, exams, targeting, display_name, userId);

    if (result.changes === 0) {
      return res.status(404).json({
        error: "User not found",
      });
    }

    res.json({
      message: "Profile updated successfully",
    });
  } catch (error) {
    console.error("PROFILE UPDATE ERROR:", error);

    res.status(500).json({
      error: "Failed to update profile.",
    });
  }
});

// ============================================================
// UPDATE STATS
// ============================================================

app.patch("/users/:kitnaId/stats", authenticateToken, (req, res) => {
  try {
    const { weekly_xp, all_time_xp, current_streak, highest_streak } = req.body;

    const result = db
      .prepare(
        `
          UPDATE users
          SET
            weekly_xp = ?,
            all_time_xp = ?,
            current_streak = ?,
            highest_streak = ?
          WHERE id = ?
          `,
      )
      .run(
        weekly_xp,
        all_time_xp,
        current_streak,
        highest_streak,
        req.user.userId,
      );

    if (result.changes === 0) {
      return res.status(404).json({
        error: "User not found",
      });
    }

    res.json({
      success: true,
    });
  } catch (error) {
    console.error("UPDATE STATS ERROR:", error);

    res.status(500).json({
      error: "Failed to update stats",
    });
  }
});

// ============================================================
// LEADERBOARD
// ============================================================

app.get("/leaderboard/:kitnaId", authenticateToken, (req, res) => {
  try {
    const userId = req.user.userId;

    const leaderboard = db
      .prepare(
        `
          SELECT
            u.kitna_id,
            u.username,
            u.display_name,
            u.pfp,
            u.weekly_xp,
            u.current_streak
          FROM users u
          JOIN friend_requests fr
            ON (
              (
                fr.sender_id = ?
                AND fr.receiver_id = u.id
              )
              OR
              (
                fr.receiver_id = ?
                AND fr.sender_id = u.id
              )
            )
          WHERE fr.status = 'accepted'

          UNION ALL

          SELECT
            u.kitna_id,
            u.username,
            u.display_name,
            u.pfp,
            u.weekly_xp,
            u.current_streak
          FROM users u
          WHERE u.id = ?

          ORDER BY weekly_xp DESC
          `,
      )
      .all(userId, userId, userId);

    res.json(leaderboard);
  } catch (error) {
    console.error("LEADERBOARD ERROR:", error);

    res.status(500).json({
      error: "Failed to load leaderboard.",
    });
  }
});

// ============================================================
// PROFILE PICTURE UPLOAD
// ============================================================

const uploadDir = path.join(
  process.env.RAILWAY_VOLUME_MOUNT_PATH || process.cwd(),
  "uploads",
);

if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

// ------------------------------------------------------------
// Multer storage
// ------------------------------------------------------------

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadDir);
  },

  filename: (req, file, cb) => {
    // IMPORTANT:
    // Do not trust the extension from
    // file.originalname.
    const filename = `${Date.now()}-${crypto.randomBytes(8).toString("hex")}`;

    cb(null, filename);
  },
});

const upload = multer({
  storage,

  limits: {
    fileSize: 5 * 1024 * 1024,
  },
});

app.use("/uploads", express.static(uploadDir));

// ------------------------------------------------------------
// Upload route
// ------------------------------------------------------------
app.patch(
  "/users/:kitnaId/pfp",

  authenticateToken,

  upload.single("pfp"),

  async (req, res) => {
    let finalPath = null;

    try {
      if (!req.file) {
        return res.status(400).json({
          error: "No image uploaded",
        });
      }

      // ------------------------------------------------------
      // Detect actual file type
      // ------------------------------------------------------

      const fileType = await fileTypeFromFile(req.file.path);

      const allowedExtensions = ["jpg", "jpeg", "png", "webp", "gif"];

      if (!fileType || !allowedExtensions.includes(fileType.ext)) {
        await fs.promises.unlink(req.file.path).catch(() => {});

        return res.status(400).json({
          error: "Only image files are allowed",
        });
      }

      // ------------------------------------------------------
      // Rename using detected extension
      // ------------------------------------------------------

      const finalFilename = `${req.file.filename}.${fileType.ext}`;

      finalPath = path.join(uploadDir, finalFilename);

      await fs.promises.rename(req.file.path, finalPath);

      const pfpPath = `/uploads/${finalFilename}`;

      // ------------------------------------------------------
      // Save to database
      // ------------------------------------------------------

      const result = db
        .prepare(
          `
          UPDATE users
          SET pfp = ?
          WHERE id = ?
          `,
        )
        .run(pfpPath, req.user.userId);

      if (result.changes === 0) {
        await fs.promises.unlink(finalPath).catch(() => {});

        return res.status(404).json({
          error: "User not found",
        });
      }

      res.json({
        success: true,
        pfp: pfpPath,
      });
    } catch (error) {
      console.error("PFP UPDATE ERROR:", error);

      // ------------------------------------------------------
      // Cleanup
      // ------------------------------------------------------

      if (finalPath) {
        await fs.promises.unlink(finalPath).catch(() => {});
      }

      if (req.file?.path) {
        await fs.promises.unlink(req.file.path).catch(() => {});
      }

      res.status(500).json({
        error: "Failed to update profile picture.",
      });
    }
  },
);

// ============================================================
// MULTER ERROR HANDLER
// ============================================================

app.use((error, req, res, next) => {
  if (error instanceof multer.MulterError) {
    if (error.code === "LIMIT_FILE_SIZE") {
      return res.status(400).json({
        error: "Image must be smaller than 5 MB.",
      });
    }

    return res.status(400).json({
      error: "Image upload failed.",
    });
  }

  if (error?.message === "Not allowed by CORS") {
    return res.status(403).json({
      error: "Request origin is not allowed.",
    });
  }

  console.error("SERVER ERROR:", error);

  res.status(500).json({
    error: "Internal server error.",
  });
});

app.listen(PORT, () => {
  console.log(`Kitna Padha backend running!`);
});
