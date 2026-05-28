require("dotenv").config();
const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
const nodemailer = require("nodemailer");
const crypto = require("crypto");

const app = express();
const server = http.createServer(app);

const io = new Server(server, {
  cors: { origin: "*", methods: ["GET", "POST"] },
});

app.use(cors());
app.use(express.json());

// ─── DATABASE ────────────────────────────────────────────────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

// ─── EMAIL ────────────────────────────────────────────────────────────────────
const mailer = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: parseInt(process.env.SMTP_PORT || "587"),
  auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
});

// ─── HELPERS ─────────────────────────────────────────────────────────────────
const JWT_SECRET = process.env.JWT_SECRET || "avipesa_secret_change_this";
const FRONTEND_URL = process.env.FRONTEND_URL || "https://your-vercel-app.vercel.app";

function signToken(userId) {
  return jwt.sign({ userId }, JWT_SECRET, { expiresIn: "30d" });
}

function authMiddleware(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith("Bearer ")) return res.status(401).json({ error: "Unauthorized" });
  try {
    const decoded = jwt.verify(header.split(" ")[1], JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch {
    res.status(401).json({ error: "Invalid or expired token" });
  }
}

function formatUser(u) {
  return {
    id: u.id,
    name: `${u.first_name} ${u.last_name}`,
    email: u.email,
    phone: u.phone,
    balance: parseFloat(u.balance),
  };
}

// ─── DB INIT ──────────────────────────────────────────────────────────────────
async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      first_name TEXT NOT NULL,
      last_name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      phone TEXT,
      password_hash TEXT NOT NULL,
      balance NUMERIC(12,2) DEFAULT 0,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS password_resets (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      token TEXT UNIQUE NOT NULL,
      expires_at TIMESTAMPTZ NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS transactions (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      type TEXT NOT NULL,
      label TEXT NOT NULL,
      amount NUMERIC(12,2) NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS game_rounds (
      id SERIAL PRIMARY KEY,
      crash_point NUMERIC(8,2) NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS game_bets (
      id SERIAL PRIMARY KEY,
      round_id INTEGER REFERENCES game_rounds(id) ON DELETE CASCADE,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      amount NUMERIC(12,2) NOT NULL,
      cashed_out BOOLEAN DEFAULT FALSE,
      cashout_mult NUMERIC(8,2),
      payout NUMERIC(12,2) DEFAULT 0,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);
  console.log("DB ready");
}

// ─── AUTH ROUTES ──────────────────────────────────────────────────────────────
app.post("/api/auth/register", async (req, res) => {
  const { firstName, lastName, email, phone, password } = req.body;
  if (!firstName || !lastName || !email || !password)
    return res.status(400).json({ error: "All fields are required" });
  if (password.length < 6)
    return res.status(400).json({ error: "Password must be at least 6 characters" });
  try {
    const exists = await pool.query("SELECT id FROM users WHERE email=$1", [email.toLowerCase()]);
    if (exists.rows.length) return res.status(409).json({ error: "Email already registered" });
    const hash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      "INSERT INTO users (first_name,last_name,email,phone,password_hash) VALUES($1,$2,$3,$4,$5) RETURNING *",
      [firstName.trim(), lastName.trim(), email.toLowerCase(), phone || "", hash]
    );
    const user = result.rows[0];
    const token = signToken(user.id);
    res.json({ token, user: formatUser(user) });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Registration failed" });
  }
});

app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: "Email and password required" });
  try {
    const result = await pool.query("SELECT * FROM users WHERE email=$1", [email.toLowerCase()]);
    if (!result.rows.length) return res.status(401).json({ error: "Invalid email or password" });
    const user = result.rows[0];
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: "Invalid email or password" });
    const token = signToken(user.id);
    res.json({ token, user: formatUser(user) });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Login failed" });
  }
});

app.get("/api/auth/me", authMiddleware, async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM users WHERE id=$1", [req.userId]);
    if (!result.rows.length) return res.status(401).json({ error: "User not found" });
    res.json({ user: formatUser(result.rows[0]) });
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/auth/forgot-password", async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: "Email required" });
  try {
    const result = await pool.query("SELECT * FROM users WHERE email=$1", [email.toLowerCase()]);
    // Always return ok to avoid email enumeration
    if (!result.rows.length) return res.json({ ok: true });
    const user = result.rows[0];
    const token = crypto.randomBytes(32).toString("hex");
    const expires = new Date(Date.now() + 1000 * 60 * 60); // 1 hour
    await pool.query("DELETE FROM password_resets WHERE user_id=$1", [user.id]);
    await pool.query(
      "INSERT INTO password_resets (user_id,token,expires_at) VALUES($1,$2,$3)",
      [user.id, token, expires]
    );
    const resetLink = `${FRONTEND_URL}?token=${token}`;
    await mailer.sendMail({
      from: `AviPesa <${process.env.SMTP_USER}>`,
      to: user.email,
      subject: "Reset your AviPesa password ✈",
      html: `
        <div style="font-family:sans-serif;max-width:480px;margin:0 auto;padding:32px;background:#070e1a;color:#dde8f5;border-radius:12px;">
          <h2 style="color:#f6c347;margin-bottom:8px;">Reset Your Password</h2>
          <p style="color:#7a90aa;margin-bottom:24px;">Click the button below to set a new password. This link expires in 1 hour.</p>
          <a href="${resetLink}" style="display:inline-block;padding:14px 28px;background:linear-gradient(135deg,#f6c347,#d4931a);color:#000;font-weight:700;border-radius:10px;text-decoration:none;">Reset Password</a>
          <p style="color:#3a4f68;font-size:12px;margin-top:24px;">If you didn't request this, ignore this email.</p>
        </div>
      `,
    });
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to send reset email" });
  }
});

app.get("/api/auth/reset-password/:token", async (req, res) => {
  const { token } = req.params;
  try {
    const result = await pool.query(
      "SELECT pr.*, u.email FROM password_resets pr JOIN users u ON u.id=pr.user_id WHERE pr.token=$1",
      [token]
    );
    if (!result.rows.length) return res.status(400).json({ valid: false, error: "Invalid token" });
    const row = result.rows[0];
    if (new Date(row.expires_at) < new Date())
      return res.status(400).json({ valid: false, error: "Token expired" });
    res.json({ valid: true, email: row.email });
  } catch (err) {
    res.status(500).json({ valid: false, error: "Server error" });
  }
});

app.post("/api/auth/reset-password", async (req, res) => {
  const { token, password } = req.body;
  if (!token || !password) return res.status(400).json({ error: "Token and password required" });
  if (password.length < 6) return res.status(400).json({ error: "Password must be at least 6 characters" });
  try {
    const result = await pool.query(
      "SELECT * FROM password_resets WHERE token=$1",
      [token]
    );
    if (!result.rows.length) return res.status(400).json({ error: "Invalid or expired token" });
    const row = result.rows[0];
    if (new Date(row.expires_at) < new Date())
      return res.status(400).json({ error: "Token expired" });
    const hash = await bcrypt.hash(password, 10);
    await pool.query("UPDATE users SET password_hash=$1 WHERE id=$2", [hash, row.user_id]);
    await pool.query("DELETE FROM password_resets WHERE token=$1", [token]);
    const userResult = await pool.query("SELECT * FROM users WHERE id=$1", [row.user_id]);
    const user = userResult.rows[0];
    const newToken = signToken(user.id);
    res.json({ ok: true, token: newToken, user: formatUser(user) });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Password reset failed" });
  }
});

// ─── WALLET ROUTES ────────────────────────────────────────────────────────────
app.post("/api/wallet/deposit", authMiddleware, async (req, res) => {
  const { amount, phone } = req.body;
  if (!amount || amount < 10) return res.status(400).json({ error: "Minimum deposit is KES 10" });
  try {
    // TODO: Integrate real Safaricom Daraja STK Push here.
    // For now this credits the wallet directly on call.
    const result = await pool.query(
      "UPDATE users SET balance=balance+$1 WHERE id=$2 RETURNING balance",
      [amount, req.userId]
    );
    const newBalance = parseFloat(result.rows[0].balance);
    await pool.query(
      "INSERT INTO transactions (user_id,type,label,amount) VALUES($1,$2,$3,$4)",
      [req.userId, "dep", "M-Pesa Deposit", amount]
    );
    res.json({ ok: true, balance: newBalance });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Deposit failed" });
  }
});

app.post("/api/wallet/withdraw", authMiddleware, async (req, res) => {
  const { amount, phone } = req.body;
  if (!amount || amount < 100) return res.status(400).json({ error: "Minimum withdrawal is KES 100" });
  try {
    const userResult = await pool.query("SELECT balance FROM users WHERE id=$1", [req.userId]);
    const currentBalance = parseFloat(userResult.rows[0].balance);
    if (amount > currentBalance) return res.status(400).json({ error: "Insufficient balance" });
    // TODO: Integrate real Safaricom Daraja B2C here.
    const result = await pool.query(
      "UPDATE users SET balance=balance-$1 WHERE id=$2 RETURNING balance",
      [amount, req.userId]
    );
    const newBalance = parseFloat(result.rows[0].balance);
    await pool.query(
      "INSERT INTO transactions (user_id,type,label,amount) VALUES($1,$2,$3,$4)",
      [req.userId, "wd", "M-Pesa Withdrawal", -amount]
    );
    res.json({ ok: true, balance: newBalance });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Withdrawal failed" });
  }
});

app.get("/api/wallet/transactions", authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM transactions WHERE user_id=$1 ORDER BY created_at DESC LIMIT 100",
      [req.userId]
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch transactions" });
  }
});

// ─── GAME ROUTES ──────────────────────────────────────────────────────────────
app.get("/api/game/leaderboard", async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        u.first_name || ' ' || LEFT(u.last_name, 1) || '***' AS name,
        COALESCE(SUM(CASE WHEN gb.cashed_out THEN gb.payout - gb.amount ELSE 0 END), 0) AS total_won,
        COUNT(gb.id) AS total_bets,
        COALESCE(MAX(gb.cashout_mult), 0) AS best_cashout
      FROM users u
      LEFT JOIN game_bets gb ON gb.user_id = u.id
      GROUP BY u.id
      ORDER BY total_won DESC
      LIMIT 10
    `);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch leaderboard" });
  }
});

app.get("/api/game/stats", authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        COUNT(*) AS "totalBets",
        COALESCE(SUM(CASE WHEN gb.cashed_out THEN gb.payout - gb.amount ELSE 0 END), 0) AS "totalWon",
        COALESCE(SUM(CASE WHEN NOT gb.cashed_out THEN gb.amount ELSE 0 END), 0) AS "totalLost",
        COALESCE(SUM(gb.amount), 0) AS "totalWagered",
        COALESCE(MAX(gb.cashout_mult), 0) AS "biggestWin",
        COALESCE(AVG(CASE WHEN gb.cashed_out THEN gb.cashout_mult END), 0) AS "avgCashout",
        COUNT(CASE WHEN gb.cashed_out THEN 1 END) AS "cashoutCount"
      FROM game_bets gb
      WHERE gb.user_id=$1
    `, [req.userId]);
    const row = result.rows[0];
    res.json({
      totalBets: parseInt(row.totalBets),
      totalWon: parseFloat(row.totalWon),
      totalLost: parseFloat(row.totalLost),
      totalWagered: parseFloat(row.totalWagered),
      biggestWin: parseFloat(row.biggestWin),
      avgCashout: parseFloat(row.avgCashout),
      cashoutCount: parseInt(row.cashoutCount),
      streak: 0,
      streakType: "win",
    });
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch stats" });
  }
});

// ─── GAME ENGINE ──────────────────────────────────────────────────────────────
const BOT_NAMES = ["KipC***","WanjiM***","OmonB***","Amina***","JohnK***","FatumA***","MwanM***","AchiB***","BrianO***","GraceN***"];

function generateCrashPoint() {
  const r = Math.random();
  if (r < 0.38) return +(1 + Math.random() * 0.8).toFixed(2);
  if (r < 0.68) return +(1.8 + Math.random() * 2.5).toFixed(2);
  if (r < 0.88) return +(4 + Math.random() * 8).toFixed(2);
  return +(12 + Math.random() * 25).toFixed(2);
}

let gameState = {
  state: "waiting",
  multiplier: 1,
  countdown: 5,
  crashPoint: 2,
  roundId: null,
  history: [],
  bets: [],
  startTime: null,
};

// User bets for current round: { socketId -> { userId, amount, cashedOut, cashMult } }
const activeBets = new Map();

// Socket -> userId map
const socketUsers = new Map();

function getBetsArray() {
  const arr = [...activeBets.values()].map(b => ({
    id: b.userId || b.socketId,
    name: b.name,
    bet: b.amount,
    cashed: b.cashedOut,
    cashMult: b.cashMult || null,
  }));
  return arr;
}

function spawnBots() {
  const count = 3 + Math.floor(Math.random() * 6);
  for (let i = 0; i < count; i++) {
    const name = BOT_NAMES[Math.floor(Math.random() * BOT_NAMES.length)];
    const amount = [25, 50, 100, 200, 500][Math.floor(Math.random() * 5)];
    activeBets.set(`bot_${i}_${Date.now()}`, {
      userId: null,
      socketId: `bot_${i}`,
      name,
      amount,
      cashedOut: false,
      cashMult: null,
      isBot: true,
      autoCashout: +(1.3 + Math.random() * 6).toFixed(2),
    });
  }
}

async function startWaiting() {
  activeBets.clear();
  gameState.state = "waiting";
  gameState.multiplier = 1;
  gameState.countdown = 5;
  gameState.bets = [];

  let round = null;
  try {
    const cp = generateCrashPoint();
    const r = await pool.query("INSERT INTO game_rounds (crash_point) VALUES($1) RETURNING id", [cp]);
    round = r.rows[0];
    gameState.roundId = round.id;
    gameState.crashPoint = cp;
  } catch (e) {
    gameState.roundId = Date.now();
    gameState.crashPoint = generateCrashPoint();
  }

  spawnBots();
  gameState.bets = getBetsArray();

  io.emit("game:waiting", {
    state: "waiting",
    countdown: gameState.countdown,
    history: gameState.history,
    bets: gameState.bets,
  });

  let c = 5;
  const cdInterval = setInterval(() => {
    c--;
    gameState.countdown = c;
    io.emit("game:countdown", { countdown: c });
    if (c <= 0) {
      clearInterval(cdInterval);
      startFlight();
    }
  }, 1000);
}

function startFlight() {
  gameState.state = "flying";
  gameState.startTime = Date.now();
  gameState.bets = getBetsArray();

  io.emit("game:flying", { state: "flying", bets: gameState.bets });

  const tick = setInterval(() => {
    const elapsed = (Date.now() - gameState.startTime) / 1000;
    const m = parseFloat(Math.pow(Math.E, elapsed * 0.35).toFixed(2));
    gameState.multiplier = m;

    // Bot auto-cashouts
    activeBets.forEach((bet, key) => {
      if (bet.isBot && !bet.cashedOut && bet.autoCashout && m >= bet.autoCashout) {
        bet.cashedOut = true;
        bet.cashMult = m;
      }
    });

    gameState.bets = getBetsArray();
    io.emit("game:tick", { multiplier: m, bets: gameState.bets });

    if (m >= gameState.crashPoint) {
      clearInterval(tick);
      endRound(m);
    }
  }, 100);
}

async function endRound(finalMult) {
  gameState.state = "crashed";
  gameState.history = [finalMult, ...gameState.history].slice(0, 12);

  // Process uncashed real user bets as losses in DB
  for (const [key, bet] of activeBets.entries()) {
    if (bet.userId && !bet.cashedOut) {
      try {
        await pool.query(
          "UPDATE game_bets SET cashed_out=false WHERE round_id=$1 AND user_id=$2",
          [gameState.roundId, bet.userId]
        );
      } catch {}
    }
  }

  gameState.bets = getBetsArray();
  io.emit("game:crashed", {
    multiplier: finalMult,
    roundId: gameState.roundId,
    bets: gameState.bets,
  });

  activeBets.clear();
  setTimeout(startWaiting, 4000);
}

// ─── SOCKET.IO ────────────────────────────────────────────────────────────────
io.on("connection", (socket) => {
  // Auth token from handshake
  const token = socket.handshake.auth?.token;
  let socketUserId = null;
  if (token) {
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      socketUserId = decoded.userId;
      socketUsers.set(socket.id, socketUserId);
    } catch {}
  }

  // Send current state immediately
  socket.emit("game:state", {
    state: gameState.state,
    multiplier: gameState.multiplier,
    countdown: gameState.countdown,
    history: gameState.history,
    bets: gameState.bets,
  });

  socket.on("bet:place", async ({ amount }) => {
    if (gameState.state !== "waiting") {
      return socket.emit("bet:result", { ok: false, error: "Betting is closed" });
    }
    if (!socketUserId) {
      return socket.emit("bet:result", { ok: false, error: "Please sign in to bet" });
    }
    if (!amount || amount < 10) {
      return socket.emit("bet:result", { ok: false, error: "Minimum bet is KES 10" });
    }
    try {
      const userResult = await pool.query("SELECT * FROM users WHERE id=$1", [socketUserId]);
      const user = userResult.rows[0];
      if (!user || parseFloat(user.balance) < amount) {
        return socket.emit("bet:result", { ok: false, error: "Insufficient balance" });
      }
      // Deduct balance
      const updated = await pool.query(
        "UPDATE users SET balance=balance-$1 WHERE id=$2 RETURNING balance",
        [amount, socketUserId]
      );
      const newBalance = parseFloat(updated.rows[0].balance);

      // Record bet in DB
      await pool.query(
        "INSERT INTO game_bets (round_id,user_id,amount) VALUES($1,$2,$3)",
        [gameState.roundId, socketUserId, amount]
      );
      await pool.query(
        "INSERT INTO transactions (user_id,type,label,amount) VALUES($1,$2,$3,$4)",
        [socketUserId, "bet", `Bet Round #${gameState.roundId}`, -amount]
      );

      // Track in memory
      activeBets.set(socket.id, {
        userId: socketUserId,
        socketId: socket.id,
        name: `${user.first_name} ${user.last_name[0]}***`,
        amount,
        cashedOut: false,
        cashMult: null,
        isBot: false,
      });

      gameState.bets = getBetsArray();
      io.emit("game:bets", gameState.bets);

      socket.emit("bet:result", { ok: true, balance: newBalance });
    } catch (err) {
      console.error(err);
      socket.emit("bet:result", { ok: false, error: "Bet failed" });
    }
  });

  socket.on("bet:cashout", async () => {
    const bet = activeBets.get(socket.id);
    if (!bet || bet.cashedOut || gameState.state !== "flying") {
      return socket.emit("cashout:result", { ok: false, error: "Cannot cash out now" });
    }
    const mult = gameState.multiplier;
    const payout = parseFloat((bet.amount * mult).toFixed(2));
    const profit = parseFloat((payout - bet.amount).toFixed(2));

    bet.cashedOut = true;
    bet.cashMult = mult;

    try {
      // Credit balance
      const updated = await pool.query(
        "UPDATE users SET balance=balance+$1 WHERE id=$2 RETURNING balance",
        [payout, bet.userId]
      );
      const newBalance = parseFloat(updated.rows[0].balance);

      // Update bet record
      await pool.query(
        "UPDATE game_bets SET cashed_out=true,cashout_mult=$1,payout=$2 WHERE round_id=$3 AND user_id=$4",
        [mult, payout, gameState.roundId, bet.userId]
      );
      await pool.query(
        "INSERT INTO transactions (user_id,type,label,amount) VALUES($1,$2,$3,$4)",
        [bet.userId, "win", `Win ×${mult.toFixed(2)}`, profit]
      );

      gameState.bets = getBetsArray();
      io.emit("game:bets", gameState.bets);

      socket.emit("cashout:result", {
        ok: true,
        mult,
        payout,
        profit,
        balance: newBalance,
      });
    } catch (err) {
      console.error(err);
      socket.emit("cashout:result", { ok: false, error: "Cashout failed" });
    }
  });

  socket.on("disconnect", () => {
    socketUsers.delete(socket.id);
    // Don't remove bet on disconnect — round still counts the loss
  });
});

// ─── START ────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3001;

initDB()
  .then(() => {
    startWaiting();
    server.listen(PORT, () => console.log(`Aviator server running on port ${PORT}`));
  })
  .catch(err => {
    console.error("DB init failed:", err);
    process.exit(1);
  });
