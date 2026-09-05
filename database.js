import Database from "better-sqlite3";
import fs from "fs";
import path from "path";

const DATA_DIR =
  process.env.RAILWAY_VOLUME_MOUNT_PATH || path.join(process.cwd(), "data");

if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

const db = new Database(path.join(DATA_DIR, "kitnapadha.db"));

/*
users
├── id
├── kitna_id
├── username
├── display_name
├── password_hash
│
├── pfp
│
├── current_streak
├── highest_streak
│
├── weekly_xp
├── all_time_xp
│
├── thoughts
├── exams
├── targeting
│
└── created_at 
 */

db.prepare(
  `
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,

        -- Identity / Auth
        kitna_id TEXT UNIQUE NOT NULL,
        username TEXT UNIQUE NOT NULL,
        display_name TEXT NOT NULL,
        password_hash TEXT NOT NULL,

        -- Profile
        pfp TEXT,

        -- Streak
        current_streak INTEGER NOT NULL DEFAULT 0,
        highest_streak INTEGER NOT NULL DEFAULT 0,

        -- XP
        weekly_xp INTEGER NOT NULL DEFAULT 0,
        all_time_xp INTEGER NOT NULL DEFAULT 0,

        -- Profile information
        thoughts TEXT DEFAULT '',
        exams TEXT DEFAULT '',
        targeting TEXT DEFAULT '',

        -- Timestamps
        created_at TEXT NOT NULL
    )
`,
).run();

db.prepare(
  `
    CREATE TABLE IF NOT EXISTS friend_requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,

        sender_id INTEGER NOT NULL,
        receiver_id INTEGER NOT NULL,

        status TEXT NOT NULL DEFAULT 'pending',

        created_at TEXT NOT NULL,

        FOREIGN KEY (sender_id) REFERENCES users(id),
        FOREIGN KEY (receiver_id) REFERENCES users(id)
    )
`,
).run();

export default db;
