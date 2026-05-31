require("dotenv").config();
const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");

const app = express();
const server = http.createServer(app);

const io = new Server(server, {
  cors: { origin: "*", methods: ["GET", "POST"] },
});

app.use(cors());
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

const JWT_SECRET = process.env.JWT_SECRET || "avipesa_secret";

function signToken(userId) {
  return jwt.sign({ userId }, JWT_SECRET, { expiresIn: "30d" });
}

function authMiddleware(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith("Bearer "))
    return res.status(401).json({ error: "Unauthorized" });
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
    phone: u.phone,
    balance: parseFloat(u.balance),
  };
}

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      first_name TEXT NOT NULL,
      last_name TEXT NOT NULL,
      phone TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      balance NUMERIC(12,2) DEFAULT 0,
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

// AUTH ROUTES

app.post("/api/auth/register", async (req, res) => {
  const { firstName, lastName, phone, password } = req.body;
  if (!firstName || !lastName || !phone || !password)
    return res.status(400).json({ error: "All fields are required" });
  if (password.length < 6)
    return res.status(400).json({ error: "Password must be at least 6 characters" });
  try {
    const exists = await pool.query("SELECT id FROM users WHERE phone=$1", [phone]);
    if (exists.rows.length)
      return res.status(409).json({ error: "Phone number already registered" });
    const hash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      "INSERT INTO users (first_name,last_name,phone,password_hash) VALUES($1,$2,$3,$4) RETURNING *",
      [firstName.trim(), lastName.trim(), phone, hash]
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
  const { phone, password } = req.body;
  if (!phone || !password)
    return res.status(400).json({ error: "Phone and password required" });
  try {
    const result = await pool.query("SELECT * FROM users WHERE phone=$1", [phone]);
    if (!result.rows.length)
      return res.status(401).json({ error: "Invalid phone or password" });
    const user = result.rows[0];
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid)
      return res.status(401).json({ error: "Invalid phone or password" });
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
    if (!result.rows.length)
      return res.status(401).json({ error: "User not found" });
    res.json({ user: formatUser(result.rows[0]) });
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

// WALLET ROUTES

app.post("/api/wallet/deposit", authMiddleware, async (req, res) => {
  const { amount } = req.body;
  if (!amount || amount < 10)
    return res.status(400).json({ error: "Minimum deposit is KES 10" });
  try {
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
  const { amount } = req.body;
  if (!amount || amount < 100)
    return res.status(400).json({ error: "Minimum withdrawal is KES 100" });
  try {
    const userResult = await pool.query("SELECT balance FROM users WHERE id=$1", [req.userId]);
    const currentBalance = parseFloat(userResult.rows[0].balance);
    if (amount > currentBalance)
      return res.status(400).json({ error: "Insufficient balance" });
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

// GAME ROUTES

app.get("/api/game/leaderboard", async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        u.first_name || ' ' || LEFT(u.last_name,1) || '***' AS name,
        COALESCE(SUM(CASE WHEN gb.cashed_out THEN gb.payout - gb.amount ELSE 0 END),0) AS total_won,
        COUNT(gb.id) AS total_bets,
        COALESCE(MAX(gb.cashout_mult),0) AS best_cashout
      FROM users u
      LEFT JOIN game_bets gb ON gb.user_id=u.id
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
        COALESCE(SUM(CASE WHEN gb.cashed_out THEN gb.payout-gb.amount ELSE 0 END),0) AS "totalWon",
        COALESCE(SUM(CASE WHEN NOT gb.cashed_out THEN gb.amount ELSE 0 END),0) AS "totalLost",
        COALESCE(SUM(gb.amount),0) AS "totalWagered",
        COALESCE(MAX(gb.cashout_mult),0) AS "biggestWin",
        COALESCE(AVG(CASE WHEN gb.cashed_out THEN gb.cashout_mult END),0) AS "avgCashout",
        COUNT(CASE WHEN gb.cashed_out THEN 1 END) AS "cashoutCount"
      FROM game_bets gb WHERE gb.user_id=$1
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

// GAME ENGINE

const BOT_NAMES = ["KipC***","WanjiM***","OmonB***","Amina***","JohnK***","FatumA***","MwanM***","AchiB***","BrianO***","GraceN***"];

function generateCrashPoint() {
  const r = Math.random();
  if (r < 0.38) return +(1 + Math.random() * 0.8).toFixed(2);
  if (r < 0.68) return +(1.8 + Math.random() * 2.5).toFixed(2);
  if (r < 0.88) return +(4 + Math.random() * 8).toFixed(2);
  return +(12 + Math.random() * 25).toFixed(2);
}

// Get exact live multiplier from elapsed time
function getLiveMultiplier() {
  if (!gameState.startTime) return 1;
  const elapsed = (Date.now() - gameState.startTime) / 1000;
  return parseFloat(Math.pow(Math.E, elapsed * 0.35).toFixed(4));
}

// Calculate ms from NOW until the multiplier reaches target
// Formula: e^(t * 0.35) = target => t = ln(target) / 0.35
function msUntilTarget(target) {
  if (!gameState.startTime) return 0;
  const tSeconds = Math.log(target) / 0.35;
  const fireAt = gameState.startTime + tSeconds * 1000;
  return Math.max(0, fireAt - Date.now());
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

const activeBets = new Map();
const socketUsers = new Map();

// socketId -> Map(panelId -> target number)
// stores the DESIRED targets set during waiting phase
const pendingAutoCashouts = new Map();

// socketId -> Map(panelId -> timerId)
// stores the active setTimeout handles during flying phase
const scheduledTimers = new Map();

function storePendingTarget(socketId, panelId, target) {
  if (!pendingAutoCashouts.has(socketId)) {
    pendingAutoCashouts.set(socketId, new Map());
  }
  if (target === null) {
    pendingAutoCashouts.get(socketId).delete(panelId);
  } else {
    pendingAutoCashouts.get(socketId).set(panelId, target);
  }
}

function getPendingTarget(socketId, panelId) {
  const panels = pendingAutoCashouts.get(socketId);
  if (!panels) return null;
  return panels.get(panelId) || null;
}

function scheduleTimer(socketId, panelId, target) {
  // Cancel existing timer for this panel if any
  cancelTimer(socketId, panelId);

  const delay = msUntilTarget(target);

  const timerId = setTimeout(async () => {
    if (gameState.state !== "flying") return;
    const betKey = panelId === 2 ? `${socketId}_2` : socketId;
    const bet = activeBets.get(betKey);
    if (!bet || bet.cashedOut) return;

    // Always pay at exact target value the player set
    const exactMult = parseFloat(target.toFixed(2));
    const result = await performCashout(bet, exactMult);
    if (result) {
      gameState.bets = getBetsArray();
      io.emit("game:bets", gameState.bets);
      const sock = io.sockets.sockets.get(socketId);
      if (sock) {
        sock.emit("cashout:result", {
          ok: true,
          mult: result.mult,
          payout: result.payout,
          profit: result.profit,
          balance: result.newBalance,
          panelId,
        });
      }
    }
  }, delay);

  if (!scheduledTimers.has(socketId)) {
    scheduledTimers.set(socketId, new Map());
  }
  scheduledTimers.get(socketId).set(panelId, timerId);
}

function cancelTimer(socketId, panelId) {
  const panels = scheduledTimers.get(socketId);
  if (!panels) return;
  const timerId = panels.get(panelId);
  if (timerId !== undefined) {
    clearTimeout(timerId);
    panels.delete(panelId);
  }
}

function cancelAllTimers() {
  scheduledTimers.forEach((panels) => {
    panels.forEach((timerId) => clearTimeout(timerId));
  });
  scheduledTimers.clear();
}

function getBetsArray() {
  return [...activeBets.values()].map(b => ({
    id: b.userId || b.socketId,
    name: b.name,
    bet: b.amount,
    cashed: b.cashedOut,
    cashMult: b.cashMult || null,
  }));
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

async function performCashout(bet, mult) {
  if (bet.cashedOut) return null;
  bet.cashedOut = true;
  bet.cashMult = mult;
  const payout = parseFloat((bet.amount * mult).toFixed(2));
  const profit = parseFloat((payout - bet.amount).toFixed(2));
  try {
    const updated = await pool.query(
      "UPDATE users SET balance=balance+$1 WHERE id=$2 RETURNING balance",
      [payout, bet.userId]
    );
    const newBalance = parseFloat(updated.rows[0].balance);
    await pool.query(
      "UPDATE game_bets SET cashed_out=true,cashout_mult=$1,payout=$2 WHERE round_id=$3 AND user_id=$4",
      [mult, payout, gameState.roundId, bet.userId]
    );
    await pool.query(
      "INSERT INTO transactions (user_id,type,label,amount) VALUES($1,$2,$3,$4)",
      [bet.userId, "win", `Win x${mult.toFixed(2)}`, profit]
    );
    return { newBalance, payout, profit, mult };
  } catch (err) {
    console.error("Cashout DB error:", err);
    bet.cashedOut = false;
    bet.cashMult = null;
    return null;
  }
}

async function startWaiting() {
  cancelAllTimers();
  activeBets.clear();
  pendingAutoCashouts.clear();

  gameState.state = "waiting";
  gameState.multiplier = 1;
  gameState.countdown = 5;
  gameState.bets = [];
  gameState.startTime = null;

  try {
    const cp = generateCrashPoint();
    const r = await pool.query(
      "INSERT INTO game_rounds (crash_point) VALUES($1) RETURNING id",
      [cp]
    );
    gameState.roundId = r.rows[0].id;
    gameState.crashPoint = cp;
  } catch {
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
  io.emit("game:flying", {
    state: "flying",
    roundId: gameState.roundId,
    bets: gameState.bets,
  });

  // Now that startTime is set, schedule all pending auto cashouts
  pendingAutoCashouts.forEach((panels, socketId) => {
    panels.forEach((target, panelId) => {
      scheduleTimer(socketId, panelId, target);
    });
  });

  // Schedule bot cashouts
  activeBets.forEach((bet) => {
    if (!bet.isBot || !bet.autoCashout) return;
    const delay = msUntilTarget(bet.autoCashout);
    setTimeout(() => {
      if (bet.cashedOut || gameState.state !== "flying") return;
      bet.cashedOut = true;
      bet.cashMult = bet.autoCashout;
    }, delay);
  });

  // Tick only for display broadcast - cashouts handled by setTimeout above
  const tick = setInterval(() => {
    const m = getLiveMultiplier();
    gameState.multiplier = m;
    gameState.bets = getBetsArray();
    io.emit("game:tick", {
      multiplier: parseFloat(m.toFixed(2)),
      bets: gameState.bets,
    });
    if (m >= gameState.crashPoint) {
      clearInterval(tick);
      endRound(parseFloat(m.toFixed(2)));
    }
  }, 100);
}

async function endRound(finalMult) {
  cancelAllTimers();
  gameState.state = "crashed";
  gameState.history = [finalMult, ...gameState.history].slice(0, 12);
  gameState.bets = getBetsArray();
  io.emit("game:crashed", {
    multiplier: finalMult,
    roundId: gameState.roundId,
    bets: gameState.bets,
  });
  activeBets.clear();
  setTimeout(startWaiting, 4000);
}

io.on("connection", (socket) => {
  const token = socket.handshake.auth?.token;
  let socketUserId = null;
  if (token) {
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      socketUserId = decoded.userId;
      socketUsers.set(socket.id, socketUserId);
    } catch {}
  }

  socket.emit("game:state", {
    state: gameState.state,
    multiplier: gameState.multiplier,
    countdown: gameState.countdown,
    history: gameState.history,
    bets: gameState.bets,
  });

  socket.on("autocashout:set", ({ target, panelId }) => {
    const pid = panelId || 1;
    const val = parseFloat(target);
    if (!isNaN(val) && val >= 1.01) {
      // Always store as pending target
      storePendingTarget(socket.id, pid, val);
      // If game is already flying, schedule immediately
      if (gameState.state === "flying") {
        scheduleTimer(socket.id, pid, val);
      }
    } else {
      // Disable auto cashout
      storePendingTarget(socket.id, pid, null);
      cancelTimer(socket.id, pid);
    }
  });

  socket.on("bet:place", async ({ amount, panelId }) => {
    if (gameState.state !== "waiting")
      return socket.emit("bet:result", { ok: false, error: "Betting is closed", panelId });
    if (!socketUserId)
      return socket.emit("bet:result", { ok: false, error: "Please sign in to bet", panelId });
    if (!amount || amount < 10)
      return socket.emit("bet:result", { ok: false, error: "Minimum bet is KES 10", panelId });
    try {
      const userResult = await pool.query("SELECT * FROM users WHERE id=$1", [socketUserId]);
      const user = userResult.rows[0];
      if (!user || parseFloat(user.balance) < amount)
        return socket.emit("bet:result", { ok: false, error: "Insufficient balance", panelId });
      const updated = await pool.query(
        "UPDATE users SET balance=balance-$1 WHERE id=$2 RETURNING balance",
        [amount, socketUserId]
      );
      const newBalance = parseFloat(updated.rows[0].balance);
      await pool.query(
        "INSERT INTO game_bets (round_id,user_id,amount) VALUES($1,$2,$3)",
        [gameState.roundId, socketUserId, amount]
      );
      await pool.query(
        "INSERT INTO transactions (user_id,type,label,amount) VALUES($1,$2,$3,$4)",
        [socketUserId, "bet", `Bet Round #${gameState.roundId}`, -amount]
      );
      const betKey = panelId === 2 ? `${socket.id}_2` : socket.id;
      activeBets.set(betKey, {
        userId: socketUserId,
        socketId: socket.id,
        betKey,
        panelId: panelId || 1,
        name: `${user.first_name} ${user.last_name[0]}***`,
        amount,
        cashedOut: false,
        cashMult: null,
        isBot: false,
      });
      gameState.bets = getBetsArray();
      io.emit("game:bets", gameState.bets);
      socket.emit("bet:result", { ok: true, balance: newBalance, amount, panelId });
    } catch (err) {
      console.error(err);
      socket.emit("bet:result", { ok: false, error: "Bet failed", panelId });
    }
  });

  socket.on("bet:cashout", async ({ panelId } = {}) => {
    if (gameState.state !== "flying")
      return socket.emit("cashout:result", { ok: false, error: "Cannot cash out now", panelId });

    const betKey = panelId === 2 ? `${socket.id}_2` : socket.id;
    const bet = activeBets.get(betKey);

    if (!bet || bet.cashedOut)
      return socket.emit("cashout:result", { ok: false, error: "Cannot cash out now", panelId });

    // Cancel auto cashout timer so it does not fire after manual cashout
    cancelTimer(socket.id, panelId || 1);

    // Use exact live multiplier at this precise millisecond
    const mult = parseFloat(getLiveMultiplier().toFixed(2));

    const result = await performCashout(bet, mult);
    if (result) {
      gameState.bets = getBetsArray();
      io.emit("game:bets", gameState.bets);
      socket.emit("cashout:result", {
        ok: true,
        mult: result.mult,
        payout: result.payout,
        profit: result.profit,
        balance: result.newBalance,
        panelId,
      });
    } else {
      socket.emit("cashout:result", { ok: false, error: "Cashout failed", panelId });
    }
  });

  socket.on("disconnect", () => {
    socketUsers.delete(socket.id);
    cancelTimer(socket.id, 1);
    cancelTimer(socket.id, 2);
    pendingAutoCashouts.delete(socket.id);
    scheduledTimers.delete(socket.id);
  });
});

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