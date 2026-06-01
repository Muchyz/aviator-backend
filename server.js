require("dotenv").config();
const express = require("express");
const http = require("http");
const crypto = require("crypto");
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

app.use("/api/wallet/paystack/webhook", express.raw({ type: "application/json" }));

app.use(cors());
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

const JWT_SECRET = process.env.JWT_SECRET || "avipesa_secret";

// ─── IN-MEMORY STATE ──────────────────────────────────────────────────────────
const activeBets = new Map();
const socketUsers = new Map();
const autoCashoutTargets = new Map();
const balanceCache = new Map();

// ─── JWT HELPERS ──────────────────────────────────────────────────────────────
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

// ─── DB INIT ──────────────────────────────────────────────────────────────────
async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      first_name TEXT NOT NULL,
      last_name TEXT NOT NULL,
      phone TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      email TEXT,
      balance NUMERIC(12,2) DEFAULT 0,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS transactions (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      type TEXT NOT NULL,
      label TEXT NOT NULL,
      amount NUMERIC(12,2) NOT NULL,
      reference TEXT UNIQUE,
      status TEXT DEFAULT 'success',
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS game_rounds (
      id SERIAL PRIMARY KEY,
      crash_point NUMERIC(8,2) NOT NULL,
      server_seed TEXT,
      server_seed_hash TEXT,
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

  await pool.query(`
    ALTER TABLE users ADD COLUMN IF NOT EXISTS email TEXT;
    ALTER TABLE transactions ADD COLUMN IF NOT EXISTS reference TEXT;
    ALTER TABLE transactions ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'success';
    ALTER TABLE game_rounds ADD COLUMN IF NOT EXISTS server_seed TEXT;
    ALTER TABLE game_rounds ADD COLUMN IF NOT EXISTS server_seed_hash TEXT;
  `);

  await pool.query(`
    DO $$
    BEGIN
      IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'transactions_reference_key'
      ) THEN
        ALTER TABLE transactions ADD CONSTRAINT transactions_reference_key UNIQUE (reference);
      END IF;
    END$$;
  `);

  console.log("DB ready");
}

// ─── PROVABLY FAIR HELPERS ────────────────────────────────────────────────────
function generateServerSeed() {
  return crypto.randomBytes(32).toString("hex");
}

function hashServerSeed(seed) {
  return crypto.createHash("sha256").update(seed).digest("hex");
}

function crashPointFromSeed(seed) {
  const hmac = crypto.createHmac("sha256", seed).update("aviator").digest("hex");
  const h = parseInt(hmac.slice(0, 8), 16);
  const e = Math.pow(2, 32);
  const raw = (100 * e - h) / (e - h);
  const result = Math.max(1.0, raw / 100);
  return parseFloat(result.toFixed(2));
}

// ─── PAYSTACK M-PESA DEPOSIT ──────────────────────────────────────────────────
app.post("/api/wallet/paystack/initiate", authMiddleware, async (req, res) => {
  const { amount, phone } = req.body;

  if (!amount || amount < 10)
    return res.status(400).json({ error: "Minimum deposit is KES 10" });
  if (!phone)
    return res.status(400).json({ error: "Phone number is required" });

  try {
    const userResult = await pool.query("SELECT * FROM users WHERE id=$1", [req.userId]);
    const user = userResult.rows[0];

    const amountInCents = Math.round(amount * 100);

    let normalizedPhone = phone.toString().trim();
    if (normalizedPhone.startsWith("0")) {
      normalizedPhone = "+254" + normalizedPhone.slice(1);
    } else if (normalizedPhone.startsWith("254")) {
      normalizedPhone = "+" + normalizedPhone;
    } else if (!normalizedPhone.startsWith("+")) {
      normalizedPhone = "+254" + normalizedPhone;
    }

    const reference = `avipesa_${req.userId}_${Date.now()}`;

    const payload = {
      email: user.email || `${user.phone}@avipesa.com`,
      amount: amountInCents,
      currency: "KES",
      mobile_money: {
        phone: normalizedPhone,
        provider: "mpesa",
      },
      reference,
      metadata: {
        userId: req.userId,
        depositAmount: amount,
      },
    };

    const response = await fetch("https://api.paystack.co/charge", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    });

    const data = await response.json();
    console.log("[PAYSTACK] initiate response:", JSON.stringify(data));

    if (!data.status) {
      return res.status(400).json({ error: data.message || "Payment initiation failed" });
    }

    await pool.query(
      `INSERT INTO transactions (user_id, type, label, amount, reference, status)
       VALUES ($1, $2, $3, $4, $5, $6)
       ON CONFLICT (reference) DO NOTHING`,
      [req.userId, "dep", "M-Pesa Deposit", amount, reference, "pending"]
    );

    res.json({
      ok: true,
      reference,
      status: data.data?.status,
      message: "STK push sent — check your phone and enter your M-Pesa PIN",
    });
  } catch (err) {
    console.error("[PAYSTACK] initiate error:", err);
    res.status(500).json({ error: "Payment initiation failed" });
  }
});

app.get("/api/wallet/paystack/verify/:reference", authMiddleware, async (req, res) => {
  const { reference } = req.params;

  try {
    const response = await fetch(
      `https://api.paystack.co/transaction/verify/${encodeURIComponent(reference)}`,
      {
        headers: {
          Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}`,
        },
      }
    );

    const data = await response.json();
    console.log("[PAYSTACK] verify response:", data.data?.status);

    if (!data.status) {
      return res.status(400).json({ error: data.message || "Verification failed" });
    }

    const txStatus = data.data?.status;

    if (txStatus === "success") {
      const existing = await pool.query(
        "SELECT * FROM transactions WHERE reference=$1 AND status='success'",
        [reference]
      );
      if (existing.rows.length) {
        const userResult = await pool.query(
          "SELECT balance FROM users WHERE id=$1",
          [req.userId]
        );
        return res.json({
          ok: true,
          status: "success",
          balance: parseFloat(userResult.rows[0].balance),
          alreadyCredited: true,
        });
      }

      const meta = data.data?.metadata;
      const depositAmount = meta?.depositAmount || data.data?.amount / 100;

      const updated = await pool.query(
        "UPDATE users SET balance=balance+$1 WHERE id=$2 RETURNING balance",
        [depositAmount, req.userId]
      );
      const newBalance = parseFloat(updated.rows[0].balance);
      balanceCache.set(req.userId, newBalance);

      await pool.query(
        "UPDATE transactions SET status='success' WHERE reference=$1",
        [reference]
      );

      console.log(
        `[PAYSTACK] credited userId=${req.userId} amount=${depositAmount} newBalance=${newBalance}`
      );
      return res.json({
        ok: true,
        status: "success",
        balance: newBalance,
        amount: depositAmount,
      });
    }

    return res.json({ ok: true, status: txStatus });
  } catch (err) {
    console.error("[PAYSTACK] verify error:", err);
    res.status(500).json({ error: "Verification failed" });
  }
});

app.post("/api/wallet/paystack/webhook", async (req, res) => {
  const signature = req.headers["x-paystack-signature"];
  const hash = crypto
    .createHmac("sha512", process.env.PAYSTACK_SECRET_KEY)
    .update(req.body)
    .digest("hex");

  if (hash !== signature) {
    console.warn("[WEBHOOK] invalid signature");
    return res.status(401).send("Invalid signature");
  }

  let event;
  try {
    event = JSON.parse(req.body);
  } catch {
    return res.status(400).send("Bad JSON");
  }

  console.log("[WEBHOOK] event:", event.event, event.data?.reference);

  if (event.event === "charge.success") {
    const { reference, metadata, amount } = event.data;
    const userId = metadata?.userId;
    const depositAmount = metadata?.depositAmount || amount / 100;

    if (!userId) return res.sendStatus(200);

    try {
      const existing = await pool.query(
        "SELECT id FROM transactions WHERE reference=$1 AND status='success'",
        [reference]
      );
      if (existing.rows.length) return res.sendStatus(200);

      const updated = await pool.query(
        "UPDATE users SET balance=balance+$1 WHERE id=$2 RETURNING balance",
        [depositAmount, userId]
      );
      const newBalance = parseFloat(updated.rows[0].balance);
      balanceCache.set(parseInt(userId), newBalance);

      await pool.query(
        "UPDATE transactions SET status='success' WHERE reference=$1",
        [reference]
      );

      console.log(`[WEBHOOK] credited userId=${userId} amount=${depositAmount}`);
    } catch (err) {
      console.error("[WEBHOOK] error:", err);
    }
  }

  res.sendStatus(200);
});

// ─── PROVABLY FAIR VERIFY ROUTE ───────────────────────────────────────────────
app.get("/api/game/verify/:roundId", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, crash_point, server_seed, server_seed_hash FROM game_rounds WHERE id=$1",
      [req.params.roundId]
    );
    if (!result.rows.length)
      return res.status(404).json({ error: "Round not found" });
    const row = result.rows[0];
    res.json({
      roundId: row.id,
      crashPoint: parseFloat(row.crash_point),
      serverSeed: row.server_seed,
      serverSeedHash: row.server_seed_hash,
    });
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch round" });
  }
});

// ─── AUTH ROUTES ──────────────────────────────────────────────────────────────
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

// ─── WALLET ROUTES ────────────────────────────────────────────────────────────
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
    const userResult = await pool.query(
      "SELECT balance FROM users WHERE id=$1",
      [req.userId]
    );
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

// ─── GAME ROUTES ──────────────────────────────────────────────────────────────
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

// ─── GAME ENGINE ──────────────────────────────────────────────────────────────
const BOT_NAMES = [
  "KipC***","WanjiM***","OmonB***","Amina***","JohnK***",
  "FatumA***","MwanM***","AchiB***","BrianO***","GraceN***"
];

function getLiveMultiplier() {
  if (!gameState.startTime) return 1;
  const elapsed = (Date.now() - gameState.startTime) / 1000;
  return parseFloat(Math.pow(Math.E, elapsed * 0.35).toFixed(4));
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
  serverSeed: null,
  serverSeedHash: null,
};

function setAutoCashoutTarget(socketId, panelId, target) {
  if (!autoCashoutTargets.has(socketId)) {
    autoCashoutTargets.set(socketId, new Map());
  }
  const panels = autoCashoutTargets.get(socketId);
  if (target === null || target === undefined) {
    panels.delete(panelId);
  } else {
    panels.set(panelId, target);
  }
  console.log(`[AUTO] set socketId=${socketId} panelId=${panelId} target=${target}`);
}

function getAutoCashoutTarget(socketId, panelId) {
  const panels = autoCashoutTargets.get(socketId);
  if (!panels) return null;
  return panels.get(panelId) || null;
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

function persistCashout(userId, roundId, mult, payout, profit) {
  pool.query(
    "UPDATE users SET balance=balance+$1 WHERE id=$2",
    [payout, userId]
  ).then(() =>
    pool.query(
      "UPDATE game_bets SET cashed_out=true,cashout_mult=$1,payout=$2 WHERE round_id=$3 AND user_id=$4",
      [mult, payout, roundId, userId]
    )
  ).then(() =>
    pool.query(
      "INSERT INTO transactions (user_id,type,label,amount) VALUES($1,$2,$3,$4)",
      [userId, "win", `Win x${mult.toFixed(2)}`, profit]
    )
  ).catch(err => {
    console.error("[CASHOUT] DB persist error:", err);
  });
}

function performCashout(bet, mult) {
  if (bet.cashedOut) {
    console.log(`[CASHOUT] already cashed out — skipping`);
    return null;
  }

  bet.cashedOut = true;
  bet.cashMult = mult;

  const payout = parseFloat((bet.amount * mult).toFixed(2));
  const profit = parseFloat((payout - bet.amount).toFixed(2));

  const cachedBal = balanceCache.get(bet.userId) || 0;
  const newBalance = parseFloat((cachedBal + payout).toFixed(2));
  balanceCache.set(bet.userId, newBalance);

  persistCashout(bet.userId, gameState.roundId, mult, payout, profit);

  console.log(`[CASHOUT] instant userId=${bet.userId} mult=${mult} payout=${payout} newBalance=${newBalance}`);
  return { newBalance, payout, profit, mult };
}

async function startWaiting() {
  activeBets.clear();

  gameState.state = "waiting";
  gameState.multiplier = 1;
  gameState.countdown = 5;
  gameState.bets = [];
  gameState.startTime = null;
  gameState.serverSeed = null;
  gameState.serverSeedHash = null;

  try {
    const serverSeed = generateServerSeed();
    const serverSeedHash = hashServerSeed(serverSeed);
    const cp = crashPointFromSeed(serverSeed);

    const r = await pool.query(
      "INSERT INTO game_rounds (crash_point, server_seed, server_seed_hash) VALUES($1,$2,$3) RETURNING id",
      [cp, serverSeed, serverSeedHash]
    );

    gameState.roundId = r.rows[0].id;
    gameState.crashPoint = cp;
    gameState.serverSeed = serverSeed;
    gameState.serverSeedHash = serverSeedHash;

    console.log(
      `[GAME] waiting roundId=${gameState.roundId} crashPoint=${cp} hash=${serverSeedHash.slice(0, 16)}...`
    );
  } catch (err) {
    console.error("[GAME] round init error:", err);
    const serverSeed = generateServerSeed();
    gameState.serverSeed = serverSeed;
    gameState.serverSeedHash = hashServerSeed(serverSeed);
    gameState.roundId = Date.now();
    gameState.crashPoint = crashPointFromSeed(serverSeed);
  }

  spawnBots();
  gameState.bets = getBetsArray();

  io.emit("game:waiting", {
    state: "waiting",
    countdown: gameState.countdown,
    history: gameState.history,
    bets: gameState.bets,
    nextHash: gameState.serverSeedHash,
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
  console.log(
    `[GAME] flying startTime=${gameState.startTime} crashPoint=${gameState.crashPoint}`
  );

  io.emit("game:flying", {
    state: "flying",
    roundId: gameState.roundId,
    bets: gameState.bets,
  });

  activeBets.forEach((bet) => {
    if (!bet.isBot || !bet.autoCashout) return;
    const tSeconds = Math.log(bet.autoCashout) / 0.35;
    const delay = Math.max(0, tSeconds * 1000);
    setTimeout(() => {
      if (bet.cashedOut || gameState.state !== "flying") return;
      bet.cashedOut = true;
      bet.cashMult = bet.autoCashout;
    }, delay);
  });

  const tick = setInterval(async () => {
    const m = getLiveMultiplier();
    gameState.multiplier = m;

    for (const [betKey, bet] of activeBets) {
      if (bet.isBot || bet.cashedOut) continue;

      const target = getAutoCashoutTarget(bet.socketId, bet.panelId);
      if (target !== null && m >= target) {
        console.log(`[AUTO] triggering betKey=${betKey} target=${target} m=${m}`);
        const cashMult = parseFloat(target.toFixed(2));
        const result = performCashout(bet, cashMult);
        if (result) {
          gameState.bets = getBetsArray();
          io.emit("game:bets", gameState.bets);
          const sock = io.sockets.sockets.get(bet.socketId);
          if (sock) {
            sock.emit("cashout:result", {
              ok: true,
              mult: result.mult,
              payout: result.payout,
              profit: result.profit,
              balance: result.newBalance,
              panelId: bet.panelId,
            });
          }
        }
      }
    }

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
  gameState.state = "crashed";
  gameState.history = [finalMult, ...gameState.history].slice(0, 12);
  gameState.bets = getBetsArray();
  console.log(
    `[GAME] crashed finalMult=${finalMult} seed=${gameState.serverSeed?.slice(0, 16)}...`
  );

  io.emit("game:crashed", {
    multiplier: finalMult,
    roundId: gameState.roundId,
    bets: gameState.bets,
    hash: gameState.serverSeedHash,
    seed: gameState.serverSeed,
  });

  activeBets.clear();
  setTimeout(startWaiting, 4000);
}

// ─── SOCKET.IO ────────────────────────────────────────────────────────────────
io.on("connection", (socket) => {
  const token = socket.handshake.auth?.token;
  let socketUserId = null;

  if (token) {
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      socketUserId = decoded.userId;
      socketUsers.set(socket.id, socketUserId);
      console.log(`[SOCKET] connected userId=${socketUserId} socketId=${socket.id}`);

      pool.query("SELECT balance FROM users WHERE id=$1", [socketUserId])
        .then(r => {
          if (r.rows.length) balanceCache.set(socketUserId, parseFloat(r.rows[0].balance));
        })
        .catch(() => {});
    } catch {}
  } else {
    console.log(`[SOCKET] connected no token socketId=${socket.id}`);
  }

  socket.emit("game:state", {
    state: gameState.state,
    multiplier: gameState.multiplier,
    countdown: gameState.countdown,
    history: gameState.history,
    bets: gameState.bets,
    nextHash: gameState.serverSeedHash,
  });

  socket.on("autocashout:set", ({ target, panelId }) => {
    const pid = parseInt(panelId) === 2 ? 2 : 1;
    const val = target !== null && target !== undefined ? parseFloat(target) : null;
    console.log(`[AUTO] autocashout:set socketId=${socket.id} panelId=${pid} target=${val}`);
    if (val !== null && !isNaN(val) && val >= 1.01) {
      setAutoCashoutTarget(socket.id, pid, val);
    } else {
      setAutoCashoutTarget(socket.id, pid, null);
    }
  });

  socket.on("bet:place", async ({ amount, panelId }) => {
    const pid = parseInt(panelId) === 2 ? 2 : 1;
    console.log(
      `[BET] bet:place socketId=${socket.id} userId=${socketUserId} amount=${amount} panelId=${pid}`
    );
    if (gameState.state !== "waiting")
      return socket.emit("bet:result", { ok: false, error: "Betting is closed", panelId: pid });
    if (!socketUserId)
      return socket.emit("bet:result", { ok: false, error: "Please sign in to bet", panelId: pid });
    if (!amount || amount < 10)
      return socket.emit("bet:result", { ok: false, error: "Minimum bet is KES 10", panelId: pid });
    try {
      const userResult = await pool.query("SELECT * FROM users WHERE id=$1", [socketUserId]);
      const user = userResult.rows[0];
      if (!user || parseFloat(user.balance) < amount)
        return socket.emit("bet:result", { ok: false, error: "Insufficient balance", panelId: pid });

      const updated = await pool.query(
        "UPDATE users SET balance=balance-$1 WHERE id=$2 RETURNING balance",
        [amount, socketUserId]
      );
      const newBalance = parseFloat(updated.rows[0].balance);
      balanceCache.set(socketUserId, newBalance);

      await pool.query(
        "INSERT INTO game_bets (round_id,user_id,amount) VALUES($1,$2,$3)",
        [gameState.roundId, socketUserId, amount]
      );
      await pool.query(
        "INSERT INTO transactions (user_id,type,label,amount) VALUES($1,$2,$3,$4)",
        [socketUserId, "bet", `Bet Round #${gameState.roundId}`, -amount]
      );

      const betKey = pid === 2 ? `${socket.id}_2` : socket.id;
      activeBets.set(betKey, {
        userId: socketUserId,
        socketId: socket.id,
        betKey,
        panelId: pid,
        name: `${user.first_name} ${user.last_name[0]}***`,
        amount,
        cashedOut: false,
        cashMult: null,
        isBot: false,
      });
      gameState.bets = getBetsArray();
      io.emit("game:bets", gameState.bets);
      socket.emit("bet:result", { ok: true, balance: newBalance, amount, panelId: pid });
      console.log(`[BET] placed betKey=${betKey} amount=${amount} newBalance=${newBalance}`);
    } catch (err) {
      console.error("[BET] error:", err);
      socket.emit("bet:result", { ok: false, error: "Bet failed", panelId: pid });
    }
  });

  socket.on("bet:cashout", ({ panelId } = {}) => {
    const pid = parseInt(panelId) === 2 ? 2 : 1;
    const mult = parseFloat(getLiveMultiplier().toFixed(2));
    console.log(
      `[CASHOUT] bet:cashout socketId=${socket.id} panelId=${pid} liveMult=${mult} gameState=${gameState.state}`
    );

    if (gameState.state !== "flying")
      return socket.emit("cashout:result", { ok: false, error: "Cannot cash out now", panelId: pid });

    const betKey = pid === 2 ? `${socket.id}_2` : socket.id;
    const bet = activeBets.get(betKey);
    console.log(`[CASHOUT] betKey=${betKey} found=${!!bet} cashedOut=${bet ? bet.cashedOut : "N/A"}`);

    if (!bet || bet.cashedOut)
      return socket.emit("cashout:result", { ok: false, error: "Cannot cash out now", panelId: pid });

    setAutoCashoutTarget(socket.id, pid, null);

    const result = performCashout(bet, mult);
    if (result) {
      gameState.bets = getBetsArray();
      io.emit("game:bets", gameState.bets);
      socket.emit("cashout:result", {
        ok: true,
        mult: result.mult,
        payout: result.payout,
        profit: result.profit,
        balance: result.newBalance,
        panelId: pid,
      });
      console.log(`[CASHOUT] instant response sent mult=${result.mult}`);
    } else {
      socket.emit("cashout:result", { ok: false, error: "Cashout failed", panelId: pid });
    }
  });

  socket.on("disconnect", () => {
    console.log(`[SOCKET] disconnected socketId=${socket.id}`);
    socketUsers.delete(socket.id);
    autoCashoutTargets.delete(socket.id);
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