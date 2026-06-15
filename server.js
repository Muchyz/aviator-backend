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
const ADMIN_SECRET = process.env.ADMIN_SECRET || "avipesa_admin_2024";

function generateAviId() {
  const num = Math.floor(1000 + Math.random() * 9000);
  return "AVI" + num;
}

async function assignAviId(userId) {
  let attempts = 0;
  while (attempts < 20) {
    const id = generateAviId();
    try {
      await pool.query("UPDATE users SET avi_id=$1 WHERE id=$2 AND avi_id IS NULL", [id, userId]);
      return id;
    } catch { attempts++; }
  }
  return null;
}

const activeBets = new Map();
const socketUsers = new Map();
const autoCashoutTargets = new Map();
const balanceCache = new Map();

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

function adminAuth(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith("Bearer "))
    return res.status(401).json({ error: "Unauthorized" });
  const token = header.split(" ")[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (!decoded.isAdmin) return res.status(403).json({ error: "Forbidden" });
    req.adminId = decoded.adminId;
    next();
  } catch {
    res.status(401).json({ error: "Invalid or expired admin token" });
  }
}

function formatUser(u) {
  return {
    id: u.id,
    name: `${u.first_name} ${u.last_name}`,
    phone: u.phone,
    balance: parseFloat(u.balance),
    aviId: u.avi_id || null,
  };
}

async function backfillAviIds() {
  try {
    const res = await pool.query("SELECT id FROM users WHERE avi_id IS NULL");
    for (const row of res.rows) await assignAviId(row.id);
    if (res.rows.length) console.log(`AVI IDs assigned to ${res.rows.length} users`);
  } catch(e) { console.error("AVI ID backfill error:", e); }
}

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
      avi_id TEXT UNIQUE,
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
    ALTER TABLE users ADD COLUMN IF NOT EXISTS avi_id TEXT;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS banned BOOLEAN DEFAULT FALSE;
    ALTER TABLE transactions ADD COLUMN IF NOT EXISTS reference TEXT;
    ALTER TABLE transactions ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'success';
    ALTER TABLE game_rounds ADD COLUMN IF NOT EXISTS server_seed TEXT;
    ALTER TABLE game_rounds ADD COLUMN IF NOT EXISTS server_seed_hash TEXT;
  `);
  console.log("DB ready");
}

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
  const rand = h / e;
  const r2 = parseInt(hmac.slice(8, 16), 16) / e;

  // Weighted distribution (per 10 rounds):
  // 2/10 -> 1.40x - 1.69x
  // 4/10 -> 2.00x - 2.83x
  // 1/10 -> 7.02x - 8.6x
  // 2/10 -> 50x+
  // 1/10 -> 3x - 6.99x (filler)

  let result;

  if (rand < 0.20) {
    result = 1.40 + r2 * 0.29;
  } else if (rand < 0.60) {
    result = 2.00 + r2 * 0.83;
  } else if (rand < 0.70) {
    result = 7.02 + r2 * 1.58;
  } else if (rand < 0.90) {
    result = 50 + Math.pow(r2, 0.6) * 36;
  } else {
    result = 3 + r2 * 3.99;
  }

  return parseFloat(Math.max(1.01, result).toFixed(2));
}

app.post("/api/wallet/paystack/initiate", authMiddleware, async (req, res) => {
  const { amount, phone } = req.body;
  if (!amount || amount < 10) return res.status(400).json({ error: "Minimum deposit is KES 10" });
  if (!phone) return res.status(400).json({ error: "Phone number is required" });
  try {
    const userResult = await pool.query("SELECT * FROM users WHERE id=$1", [req.userId]);
    const user = userResult.rows[0];
    const amountInCents = Math.round(amount * 100);
    let p = phone.toString().trim();
    if (p.startsWith("0")) p = "+254" + p.slice(1);
    else if (p.startsWith("254")) p = "+" + p;
    else if (!p.startsWith("+")) p = "+254" + p;
    const reference = `avipesa_${req.userId}_${Date.now()}`;
    const response = await fetch("https://api.paystack.co/charge", {
      method: "POST",
      headers: { Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}`, "Content-Type": "application/json" },
      body: JSON.stringify({ email: user.email || `${user.phone}@avipesa.com`, amount: amountInCents, currency: "KES", mobile_money: { phone: p, provider: "mpesa" }, reference, metadata: { userId: req.userId, depositAmount: amount } }),
    });
    const data = await response.json();
    if (!data.status) return res.status(400).json({ error: data.message || "Payment initiation failed" });
    await pool.query(`INSERT INTO transactions (user_id,type,label,amount,reference,status) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (reference) DO NOTHING`, [req.userId, "dep", "M-Pesa Deposit", amount, reference, "pending"]);
    res.json({ ok: true, reference, status: data.data?.status, message: "STK push sent" });
  } catch (err) { res.status(500).json({ error: "Payment initiation failed" }); }
});

app.get("/api/wallet/paystack/verify/:reference", authMiddleware, async (req, res) => {
  try {
    const response = await fetch(`https://api.paystack.co/transaction/verify/${encodeURIComponent(req.params.reference)}`, { headers: { Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}` } });
    const data = await response.json();
    if (!data.status) return res.status(400).json({ error: data.message || "Verification failed" });
    const txStatus = data.data?.status;
    if (txStatus === "success") {
      const depositAmount = data.data?.metadata?.depositAmount || data.data?.amount / 100;
      const credited = await pool.query(
        "UPDATE transactions SET status='success' WHERE reference=$1 AND status='pending' RETURNING id",
        [req.params.reference]
      );
      if (credited.rows.length === 0) {
        const u = await pool.query("SELECT balance FROM users WHERE id=$1", [req.userId]);
        return res.json({ ok: true, status: "success", balance: parseFloat(u.rows[0].balance), alreadyCredited: true });
      }
      const updated = await pool.query("UPDATE users SET balance=balance+$1 WHERE id=$2 RETURNING balance", [depositAmount, req.userId]);
      balanceCache.set(req.userId, parseFloat(updated.rows[0].balance));
      return res.json({ ok: true, status: "success", balance: parseFloat(updated.rows[0].balance), amount: depositAmount });
    }
    return res.json({ ok: true, status: txStatus });
  } catch { res.status(500).json({ error: "Verification failed" }); }
});

app.post("/api/wallet/paystack/webhook", async (req, res) => {
  const hash = crypto.createHmac("sha512", process.env.PAYSTACK_SECRET_KEY).update(req.body).digest("hex");
  if (hash !== req.headers["x-paystack-signature"]) return res.status(401).send("Invalid signature");
  let event;
  try { event = JSON.parse(req.body); } catch { return res.status(400).send("Bad JSON"); }
  if (event.event === "charge.success") {
    const { reference, metadata, amount } = event.data;
    const userId = metadata?.userId;
    const depositAmount = metadata?.depositAmount || amount / 100;
    if (!userId) return res.sendStatus(200);
    try {
      const existing = await pool.query("SELECT id FROM transactions WHERE reference=$1 AND status='success'", [reference]);
      if (!existing.rows.length) {
        const updated = await pool.query("UPDATE users SET balance=balance+$1 WHERE id=$2 RETURNING balance", [depositAmount, userId]);
        balanceCache.set(parseInt(userId), parseFloat(updated.rows[0].balance));
        await pool.query("UPDATE transactions SET status='success' WHERE reference=$1", [reference]);
      }
    } catch (err) { console.error(err); }
  }
  res.sendStatus(200);
});

app.post("/api/auth/register", async (req, res) => {
  const { firstName, lastName, phone, password } = req.body;
  if (!firstName || !lastName || !phone || !password) return res.status(400).json({ error: "All fields are required" });
  if (password.length < 6) return res.status(400).json({ error: "Password must be at least 6 characters" });
  try {
    const exists = await pool.query("SELECT id FROM users WHERE phone=$1", [phone]);
    if (exists.rows.length) return res.status(409).json({ error: "Phone number already registered" });
    const hash = await bcrypt.hash(password, 10);
    const result = await pool.query("INSERT INTO users (first_name,last_name,phone,password_hash) VALUES($1,$2,$3,$4) RETURNING *", [firstName.trim(), lastName.trim(), phone, hash]);
    await assignAviId(result.rows[0].id);
    const finalUser = await pool.query("SELECT * FROM users WHERE id=$1", [result.rows[0].id]);
    result.rows[0] = finalUser.rows[0];
    res.json({ token: signToken(result.rows[0].id), user: formatUser(result.rows[0]) });
  } catch(err) { console.error("[REGISTER]", err); res.status(500).json({ error: err.message || "Registration failed" }); }
});

app.post("/api/auth/login", async (req, res) => {
  const { phone, password } = req.body;
  if (!phone || !password) return res.status(400).json({ error: "Phone and password required" });
  try {
    const result = await pool.query("SELECT * FROM users WHERE phone=$1", [phone]);
    if (!result.rows.length) return res.status(401).json({ error: "Invalid phone or password" });
    const user = result.rows[0];
    if (!(await bcrypt.compare(password, user.password_hash))) return res.status(401).json({ error: "Invalid phone or password" });
    res.json({ token: signToken(user.id), user: formatUser(user) });
  } catch { res.status(500).json({ error: "Login failed" }); }
});

app.get("/api/auth/me", authMiddleware, async (req, res) => {
  try {
    const result = await pool.query("SELECT id,first_name,last_name,phone,balance,avi_id FROM users WHERE id=$1", [req.userId]);
    if (!result.rows.length) return res.status(401).json({ error: "User not found" });
    res.json({ user: formatUser(result.rows[0]) });
  } catch { res.status(500).json({ error: "Server error" }); }
});

// Direct deposit endpoint removed - use /api/wallet/paystack/initiate instead

app.post("/api/wallet/withdraw", authMiddleware, async (req, res) => {
  const { amount } = req.body;
  if (!amount || amount < 100) return res.status(400).json({ error: "Minimum withdrawal is KES 100" });
  try {
    const u = await pool.query("SELECT balance FROM users WHERE id=$1", [req.userId]);
    if (amount > parseFloat(u.rows[0].balance)) return res.status(400).json({ error: "Insufficient balance" });
    const result = await pool.query("UPDATE users SET balance=balance-$1 WHERE id=$2 RETURNING balance", [amount, req.userId]);
    await pool.query("INSERT INTO transactions (user_id,type,label,amount) VALUES($1,$2,$3,$4)", [req.userId, "wd", "M-Pesa Withdrawal", -amount]);
    res.json({ ok: true, balance: parseFloat(result.rows[0].balance) });
  } catch { res.status(500).json({ error: "Withdrawal failed" }); }
});

app.get("/api/wallet/transactions", authMiddleware, async (req, res) => {
  try {
    const result = await pool.query("SELECT id, type, label, amount, status, reference, created_at FROM transactions WHERE user_id=$1 ORDER BY created_at DESC LIMIT 100", [req.userId]);
    res.json(result.rows);
  } catch { res.status(500).json({ error: "Failed to fetch transactions" }); }
});

app.get("/api/game/leaderboard", async (req, res) => {
  try {
    const result = await pool.query(`SELECT u.first_name||' '||LEFT(u.last_name,1)||'***' AS name, COALESCE(SUM(CASE WHEN gb.cashed_out THEN gb.payout-gb.amount ELSE 0 END),0) AS total_won, COUNT(gb.id) AS total_bets, COALESCE(MAX(gb.cashout_mult),0) AS best_cashout FROM users u LEFT JOIN game_bets gb ON gb.user_id=u.id GROUP BY u.id ORDER BY total_won DESC LIMIT 10`);
    res.json(result.rows);
  } catch { res.status(500).json({ error: "Failed to fetch leaderboard" }); }
});

app.get("/api/game/stats", authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(`SELECT COUNT(*) AS "totalBets", COALESCE(SUM(CASE WHEN gb.cashed_out THEN gb.payout-gb.amount ELSE 0 END),0) AS "totalWon", COALESCE(SUM(CASE WHEN NOT gb.cashed_out THEN gb.amount ELSE 0 END),0) AS "totalLost", COALESCE(SUM(gb.amount),0) AS "totalWagered", COALESCE(MAX(gb.cashout_mult),0) AS "biggestWin", COALESCE(AVG(CASE WHEN gb.cashed_out THEN gb.cashout_mult END),0) AS "avgCashout", COUNT(CASE WHEN gb.cashed_out THEN 1 END) AS "cashoutCount" FROM game_bets gb WHERE gb.user_id=$1`, [req.userId]);
    const row = result.rows[0];
    res.json({ totalBets: parseInt(row.totalBets), totalWon: parseFloat(row.totalWon), totalLost: parseFloat(row.totalLost), totalWagered: parseFloat(row.totalWagered), biggestWin: parseFloat(row.biggestWin), avgCashout: parseFloat(row.avgCashout), cashoutCount: parseInt(row.cashoutCount), streak: 0, streakType: "win" });
  } catch { res.status(500).json({ error: "Failed to fetch stats" }); }
});

app.get("/api/game/verify/:roundId", async (req, res) => {
  try {
    const result = await pool.query("SELECT id,crash_point,server_seed,server_seed_hash FROM game_rounds WHERE id=$1", [req.params.roundId]);
    if (!result.rows.length) return res.status(404).json({ error: "Round not found" });
    const row = result.rows[0];
    res.json({ roundId: row.id, crashPoint: parseFloat(row.crash_point), serverSeed: row.server_seed, serverSeedHash: row.server_seed_hash });
  } catch { res.status(500).json({ error: "Failed to fetch round" }); }
});

app.post("/api/admin/login", (req, res) => {
  const { secret } = req.body;
  if (!secret || secret !== ADMIN_SECRET) return res.status(401).json({ error: "Invalid admin secret" });
  const token = jwt.sign({ isAdmin: true, adminId: "admin" }, JWT_SECRET, { expiresIn: "12h" });
  res.json({ token });
});

app.get("/api/admin/overview", adminAuth, async (req, res) => {
  try {
    const [deps, wds, bets, wins, users, rounds] = await Promise.all([
      pool.query(`SELECT COALESCE(SUM(amount),0) AS total FROM transactions WHERE type='dep' AND status='success'`),
      pool.query(`SELECT COALESCE(SUM(ABS(amount)),0) AS total FROM transactions WHERE type='wd'`),
      pool.query(`SELECT COALESCE(SUM(ABS(amount)),0) AS total FROM transactions WHERE type='bet'`),
      pool.query(`SELECT COALESCE(SUM(amount),0) AS total FROM transactions WHERE type='win'`),
      pool.query(`SELECT COUNT(*) AS total FROM users`),
      pool.query(`SELECT COUNT(*) AS total FROM game_rounds`),
    ]);
    const todayStart = new Date(); todayStart.setHours(0,0,0,0);
    const [depsToday, newUsers] = await Promise.all([
      pool.query(`SELECT COALESCE(SUM(amount),0) AS total FROM transactions WHERE type='dep' AND status='success' AND created_at >= $1`, [todayStart]),
      pool.query(`SELECT COUNT(*) AS total FROM users WHERE created_at >= $1`, [todayStart]),
    ]);
    res.json({ totalDeposits: parseFloat(deps.rows[0].total), totalWithdrawals: parseFloat(wds.rows[0].total), totalBetsPlaced: parseFloat(bets.rows[0].total), totalWinsPaid: parseFloat(wins.rows[0].total), houseProfit: parseFloat((parseFloat(bets.rows[0].total)-parseFloat(wins.rows[0].total)).toFixed(2)), totalUsers: parseInt(users.rows[0].total), totalRounds: parseInt(rounds.rows[0].total), depositsToday: parseFloat(depsToday.rows[0].total), newUsersToday: parseInt(newUsers.rows[0].total) });
  } catch (err) { res.status(500).json({ error: "Failed to fetch overview" }); }
});

app.get("/api/admin/users", adminAuth, async (req, res) => {
  const { search = "", page = 1, limit = 30 } = req.query;
  const offset = (parseInt(page)-1)*parseInt(limit);
  try {
    const q = `%${search}%`;
    const result = await pool.query(`SELECT u.id,u.first_name,u.last_name,u.phone,u.balance,u.created_at,u.banned,COUNT(gb.id) AS total_bets,COALESCE(SUM(CASE WHEN gb.cashed_out THEN gb.payout-gb.amount ELSE 0 END),0) AS total_won FROM users u LEFT JOIN game_bets gb ON gb.user_id=u.id WHERE u.phone ILIKE $1 OR u.first_name ILIKE $1 OR u.last_name ILIKE $1 GROUP BY u.id ORDER BY u.created_at DESC LIMIT $2 OFFSET $3`, [q, parseInt(limit), offset]);
    const count = await pool.query(`SELECT COUNT(*) FROM users WHERE phone ILIKE $1 OR first_name ILIKE $1 OR last_name ILIKE $1`, [q]);
    res.json({ users: result.rows, total: parseInt(count.rows[0].count) });
  } catch { res.status(500).json({ error: "Failed to fetch users" }); }
});

app.get("/api/admin/users/:id", adminAuth, async (req, res) => {
  try {
    const user = await pool.query("SELECT id,first_name,last_name,phone,balance,created_at,banned FROM users WHERE id=$1", [req.params.id]);
    if (!user.rows.length) return res.status(404).json({ error: "User not found" });
    const txns = await pool.query("SELECT * FROM transactions WHERE user_id=$1 ORDER BY created_at DESC LIMIT 50", [req.params.id]);
    const bets = await pool.query("SELECT gb.*,gr.crash_point FROM game_bets gb LEFT JOIN game_rounds gr ON gr.id=gb.round_id WHERE gb.user_id=$1 ORDER BY gb.created_at DESC LIMIT 50", [req.params.id]);
    res.json({ user: user.rows[0], transactions: txns.rows, bets: bets.rows });
  } catch { res.status(500).json({ error: "Failed to fetch user detail" }); }
});

app.post("/api/admin/users/:id/balance", adminAuth, async (req, res) => {
  const { amount, note } = req.body;
  const parsed = parseFloat(amount);
  if (isNaN(parsed) || parsed === 0) return res.status(400).json({ error: "Invalid amount" });
  try {
    const updated = await pool.query("UPDATE users SET balance=balance+$1 WHERE id=$2 RETURNING balance", [parsed, req.params.id]);
    if (updated.rows.length === 0) return res.status(404).json({ error: "User not found" });
    const txType = parsed > 0 ? "dep" : "wd";
    const txLabel = note || (parsed > 0 ? "Admin credit" : "Admin debit");
    await pool.query("INSERT INTO transactions (user_id,type,label,amount) VALUES($1,$2,$3,$4)", [req.params.id, txType, txLabel, parsed]);
    res.json({ ok: true, balance: parseFloat(updated.rows[0].balance) });
  } catch(err) {
    console.error(err);
    res.status(500).json({ error: "Failed to adjust balance" });
  }
});

app.post("/api/admin/users/:id/ban", adminAuth, async (req, res) => {
  const { banned } = req.body;
  try {
    await pool.query("UPDATE users SET banned=$1 WHERE id=$2", [!!banned, req.params.id]);
    res.json({ ok: true, banned: !!banned });
  } catch { res.status(500).json({ error: "Failed to update ban status" }); }
});

app.get("/api/admin/transactions", adminAuth, async (req, res) => {
  const { type = "", page = 1, limit = 50 } = req.query;
  const offset = (parseInt(page)-1)*parseInt(limit);
  try {
    let result, count;
    if (type) {
      result = await pool.query(
        `SELECT t.*,u.first_name,u.last_name,u.phone FROM transactions t LEFT JOIN users u ON u.id=t.user_id WHERE t.type=$1 ORDER BY t.created_at DESC LIMIT $2 OFFSET $3`,
        [type, parseInt(limit), offset]
      );
      count = await pool.query(`SELECT COUNT(*) FROM transactions WHERE type=$1`, [type]);
    } else {
      result = await pool.query(
        `SELECT t.*,u.first_name,u.last_name,u.phone FROM transactions t LEFT JOIN users u ON u.id=t.user_id ORDER BY t.created_at DESC LIMIT $1 OFFSET $2`,
        [parseInt(limit), offset]
      );
      count = await pool.query(`SELECT COUNT(*) FROM transactions`);
    }
    res.json({ transactions: result.rows, total: parseInt(count.rows[0].count) });
  } catch(err) {
    console.error(err);
    res.status(500).json({ error: "Failed to fetch transactions" });
  }
});

app.get("/api/admin/rounds", adminAuth, async (req, res) => {
  const { page = 1, limit = 50 } = req.query;
  const offset = (parseInt(page)-1)*parseInt(limit);
  try {
    const result = await pool.query(`SELECT gr.*,COUNT(gb.id) AS bet_count,COALESCE(SUM(gb.amount),0) AS total_wagered,COALESCE(SUM(CASE WHEN gb.cashed_out THEN gb.payout ELSE 0 END),0) AS total_paid FROM game_rounds gr LEFT JOIN game_bets gb ON gb.round_id=gr.id GROUP BY gr.id ORDER BY gr.created_at DESC LIMIT $1 OFFSET $2`, [parseInt(limit), offset]);
    const count = await pool.query("SELECT COUNT(*) FROM game_rounds");
    res.json({ rounds: result.rows, total: parseInt(count.rows[0].count) });
  } catch { res.status(500).json({ error: "Failed to fetch rounds" }); }
});

app.get("/api/admin/live", adminAuth, (req, res) => {
  res.json({ state: gameState.state, multiplier: gameState.multiplier, crashPoint: gameState.crashPoint, roundId: gameState.roundId, countdown: gameState.countdown, activeBets: [...activeBets.values()].map(b=>({name:b.name,amount:b.amount,cashedOut:b.cashedOut,cashMult:b.cashMult,isBot:b.isBot})), history: gameState.history });
});

app.get("/api/admin/gamestats", adminAuth, async (req, res) => {
  try {
    const result = await pool.query(`SELECT COUNT(*) AS total_rounds,AVG(crash_point) AS avg_crash,MAX(crash_point) AS max_crash,MIN(crash_point) AS min_crash,COUNT(CASE WHEN crash_point<2 THEN 1 END) AS under_2x,COUNT(CASE WHEN crash_point>=2 AND crash_point<5 THEN 1 END) AS btw_2_5x,COUNT(CASE WHEN crash_point>=5 AND crash_point<10 THEN 1 END) AS btw_5_10x,COUNT(CASE WHEN crash_point>=10 THEN 1 END) AS over_10x FROM game_rounds`);
    res.json(result.rows[0]);
  } catch { res.status(500).json({ error: "Failed to fetch game stats" }); }
});

const BOT_NAMES = [
  "KipC***","WanjiM***","OmonB***","Amina***","JohnK***","FatumA***","MwanM***",
  "NjorO***","KamauW***","AchiD***","BarasaO***","WaweruJ***","NyamboG***",
  "ChepkN***","MutisoP***","AkinyiL***","OdedaR***","KiptooS***","MumboT***",
  "WambuiK***","OtienoH***","NdunguF***","MwendeC***","KilonzoB***","RutoA***",
  "NjokiV***","MaingiE***","SitatiZ***","KemboiQ***","AuduU***","WafulaY***",
  "MugoX***","KarimiI***","OkothJ***","ChelangaO***","BiwottN***","MakoryaM***",
  "KiplagN***","MwauraT***","NyongoS***","TumaJ***","WekesaR***","OchiengD***",
  "KipkoechL***","NaliakaP***","MuthoniB***","GachieK***","RotichV***","OmondiZ***",
  "AwinoQ***","MutuaC***","WairimuG***","CherutoH***","SilantoiY***","ImaliF***",
  "NyaboLs***","KipruE***","MasinoT***","AchengW***","BosireU***","LangatI***",
  "MboyaJ***","KinyuaA***","NyakioR***","OumaB***","SangN***","TanuiX***",
  "WafutaM***","YusufO***","ZawadiK***","AdongoP***","BetancoK***"
];

function shuffledBotNames() {
  const arr = [...BOT_NAMES];
  for (let i = arr.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr;
}

function randomAviId() {
  return BOT_NAMES[Math.floor(Math.random() * BOT_NAMES.length)];
}

let gameState = { state:"waiting", multiplier:1, countdown:5, crashPoint:2, roundId:null, history:[], bets:[], startTime:null, serverSeed:null, serverSeedHash:null };

function getLiveMultiplier() {
  if (!gameState.startTime) return 1;
  return parseFloat(Math.pow(Math.E,(Date.now()-gameState.startTime)/1000*0.35).toFixed(4));
}

function setAutoCashoutTarget(socketId,panelId,target) {
  if (!autoCashoutTargets.has(socketId)) autoCashoutTargets.set(socketId,new Map());
  const panels = autoCashoutTargets.get(socketId);
  if (target===null||target===undefined) panels.delete(panelId);
  else panels.set(panelId,target);
}

function getAutoCashoutTarget(socketId,panelId) {
  const panels = autoCashoutTargets.get(socketId);
  return panels ? (panels.get(panelId)||null) : null;
}

function getBetsArray() {
  return [...activeBets.values()].map(b=>({id:b.userId||b.socketId,name:b.name,bet:b.amount,cashed:b.cashedOut,cashMult:b.cashMult||null}));
}

function spawnBots() {
  const count = 30 + Math.floor(Math.random() * 31);
  const betOptions = [10,25,50,100,200,500,1000,2000,5000];
  const namePool = shuffledBotNames();
  for (let i = 0; i < count; i++) {
    const key = `bot_${i}_${Date.now()}`;
    let name;
    if (i < namePool.length) {
      name = namePool[i];
    } else {
      const base = namePool[i % namePool.length];
      name = `${base}${Math.floor(10 + Math.random() * 90)}`;
    }
    activeBets.set(key, {
      userId: null,
      socketId: key,
      name,
      amount: betOptions[Math.floor(Math.random() * betOptions.length)],
      cashedOut: false,
      cashMult: null,
      isBot: true,
      autoCashout: +(1.2 + Math.random() * 8).toFixed(2),
    });
  }
}

function persistCashout(userId,roundId,mult,payout,profit) {
  pool.query("UPDATE users SET balance=balance+$1 WHERE id=$2",[payout,userId])
    .then(()=>pool.query("UPDATE game_bets SET cashed_out=true,cashout_mult=$1,payout=$2 WHERE round_id=$3 AND user_id=$4",[mult,payout,roundId,userId]))
    .then(()=>pool.query("INSERT INTO transactions (user_id,type,label,amount) VALUES($1,$2,$3,$4)",[userId,"win",`Win x${mult.toFixed(2)}`,profit]))
    .catch(err=>console.error("[CASHOUT]",err));
}

function performCashout(bet,mult) {
  if (bet.cashedOut) return null;
  bet.cashedOut=true; bet.cashMult=mult;
  const payout=parseFloat((bet.amount*mult).toFixed(2));
  const profit=parseFloat((payout-bet.amount).toFixed(2));
  const newBalance=parseFloat(((balanceCache.get(bet.userId)||0)+payout).toFixed(2));
  balanceCache.set(bet.userId,newBalance);
  persistCashout(bet.userId,gameState.roundId,mult,payout,profit);
  return {newBalance,payout,profit,mult};
}

async function startWaiting() {
  if (gameConfig.paused) {
    setTimeout(startWaiting, 2000);
    return;
  }
  activeBets.clear();
  gameState={...gameState,state:"waiting",multiplier:1,countdown:5,bets:[],startTime:null};
  try {
    const serverSeed=generateServerSeed();
    const serverSeedHash=hashServerSeed(serverSeed);
    const cp=crashPointFromSeed(serverSeed);
    const r=await pool.query("INSERT INTO game_rounds (crash_point,server_seed,server_seed_hash) VALUES($1,$2,$3) RETURNING id",[cp,serverSeed,serverSeedHash]);
    gameState.roundId=r.rows[0].id; gameState.crashPoint=cp; gameState.serverSeed=serverSeed; gameState.serverSeedHash=serverSeedHash;
  } catch(err) {
    console.error("[GAME]",err);
    const s=generateServerSeed(); gameState.serverSeed=s; gameState.serverSeedHash=hashServerSeed(s); gameState.roundId=Date.now(); gameState.crashPoint=crashPointFromSeed(s);
  }
  spawnBots(); gameState.bets=getBetsArray();
  io.emit("game:waiting",{state:"waiting",countdown:gameState.countdown,history:gameState.history,bets:gameState.bets,nextHash:gameState.serverSeedHash});
  let c=5;
  const cdInterval=setInterval(()=>{
    c--; gameState.countdown=c; io.emit("game:countdown",{countdown:c});
    if(c<=0){clearInterval(cdInterval);startFlight();}
  },1000);
}

function startFlight() {
  gameState.state="flying"; gameState.startTime=Date.now(); gameState.bets=getBetsArray();
  io.emit("game:flying",{state:"flying",roundId:gameState.roundId,bets:gameState.bets});
  activeBets.forEach(bet=>{
    if(!bet.isBot||!bet.autoCashout) return;
    setTimeout(()=>{if(bet.cashedOut||gameState.state!=="flying")return;bet.cashedOut=true;bet.cashMult=bet.autoCashout;},Math.max(0,(Math.log(bet.autoCashout)/0.35)*1000));
  });
  const tick=setInterval(async()=>{
    const m=getLiveMultiplier(); gameState.multiplier=m;
    for(const [betKey,bet] of activeBets){
      if(bet.isBot||bet.cashedOut) continue;
      const target=getAutoCashoutTarget(bet.socketId,bet.panelId);
      if(target!==null&&m>=target){
        const result=performCashout(bet,parseFloat(target.toFixed(2)));
        if(result){
          gameState.bets=getBetsArray(); io.emit("game:bets",gameState.bets);
          const sock=io.sockets.sockets.get(bet.socketId);
          if(sock) sock.emit("cashout:result",{ok:true,mult:result.mult,payout:result.payout,profit:result.profit,balance:result.newBalance,panelId:bet.panelId});
        }
      }
    }
    gameState.bets=getBetsArray(); io.emit("game:tick",{multiplier:parseFloat(m.toFixed(2)),bets:gameState.bets});
    if(m>=gameState.crashPoint){clearInterval(tick);endRound(parseFloat(m.toFixed(2)));}
  },100);
}

async function endRound(finalMult) {
  gameState.state="crashed"; gameState.history=[finalMult,...gameState.history].slice(0,12); gameState.bets=getBetsArray();
  io.emit("game:crashed",{multiplier:finalMult,roundId:gameState.roundId,bets:gameState.bets,hash:gameState.serverSeedHash,seed:gameState.serverSeed});
  activeBets.clear(); setTimeout(startWaiting,4000);
}

io.on("connection",(socket)=>{
  const token=socket.handshake.auth?.token;
  let socketUserId=null;
  if(token){try{const d=jwt.verify(token,JWT_SECRET);socketUserId=d.userId;socketUsers.set(socket.id,socketUserId);pool.query("SELECT balance FROM users WHERE id=$1",[socketUserId]).then(r=>{if(r.rows.length)balanceCache.set(socketUserId,parseFloat(r.rows[0].balance));}).catch(()=>{});}catch{}}
  socket.emit("game:state",{state:gameState.state,multiplier:gameState.multiplier,countdown:gameState.countdown,history:gameState.history,bets:gameState.bets,nextHash:gameState.serverSeedHash});
  socket.on("autocashout:set",({target,panelId})=>{const pid=parseInt(panelId)===2?2:1;const val=target!==null&&target!==undefined?parseFloat(target):null;if(val!==null&&!isNaN(val)&&val>=1.01)setAutoCashoutTarget(socket.id,pid,val);else setAutoCashoutTarget(socket.id,pid,null);});
  socket.on("bet:place",async({amount,panelId})=>{
    const pid=parseInt(panelId)===2?2:1;
    if(gameState.state!=="waiting") return socket.emit("bet:result",{ok:false,error:"Betting is closed",panelId:pid});
    if(!socketUserId) return socket.emit("bet:result",{ok:false,error:"Please sign in to bet",panelId:pid});
    if(!amount||amount<10) return socket.emit("bet:result",{ok:false,error:"Minimum bet is KES 10",panelId:pid});
    try{
      const u=await pool.query("SELECT id,first_name,last_name,balance,banned,avi_id FROM users WHERE id=$1",[socketUserId]);
      const user=u.rows[0];
      if(!user||parseFloat(user.balance)<amount) return socket.emit("bet:result",{ok:false,error:"Insufficient balance",panelId:pid});
      const updated=await pool.query("UPDATE users SET balance=balance-$1 WHERE id=$2 RETURNING balance",[amount,socketUserId]);
      const newBalance=parseFloat(updated.rows[0].balance); balanceCache.set(socketUserId,newBalance);
      await pool.query("INSERT INTO game_bets (round_id,user_id,amount) VALUES($1,$2,$3)",[gameState.roundId,socketUserId,amount]);
      await pool.query("INSERT INTO transactions (user_id,type,label,amount) VALUES($1,$2,$3,$4)",[socketUserId,"bet",`Bet Round #${gameState.roundId}`,-amount]);
      const betKey=pid===2?`${socket.id}_2`:socket.id;
      const displayName = user.avi_id || randomAviId();
      activeBets.set(betKey,{userId:socketUserId,socketId:socket.id,betKey,panelId:pid,name:displayName,amount,cashedOut:false,cashMult:null,isBot:false});
      gameState.bets=getBetsArray(); io.emit("game:bets",gameState.bets);
      socket.emit("bet:result",{ok:true,balance:newBalance,amount,panelId:pid});
    }catch{socket.emit("bet:result",{ok:false,error:"Bet failed",panelId:pid});}
  });
  socket.on("bet:cashout",({panelId}={})=>{
    const pid=parseInt(panelId)===2?2:1;
    const mult=parseFloat(getLiveMultiplier().toFixed(2));
    if(gameState.state!=="flying") return socket.emit("cashout:result",{ok:false,error:"Cannot cash out now",panelId:pid});
    const betKey=pid===2?`${socket.id}_2`:socket.id;
    const bet=activeBets.get(betKey);
    if(!bet||bet.cashedOut) return socket.emit("cashout:result",{ok:false,error:"Cannot cash out now",panelId:pid});
    setAutoCashoutTarget(socket.id,pid,null);
    const result=performCashout(bet,mult);
    if(result){gameState.bets=getBetsArray();io.emit("game:bets",gameState.bets);socket.emit("cashout:result",{ok:true,mult:result.mult,payout:result.payout,profit:result.profit,balance:result.newBalance,panelId:pid});}
    else socket.emit("cashout:result",{ok:false,error:"Cashout failed",panelId:pid});
  });
  socket.on("disconnect",()=>{socketUsers.delete(socket.id);autoCashoutTargets.delete(socket.id);});
});


// ── ADMIN REPORTS ─────────────────────────────────────────────────────────────
app.get("/api/admin/reports/daily", adminAuth, async (req, res) => {
  try {
    const today = new Date(); today.setHours(0,0,0,0);
    const yesterday = new Date(today); yesterday.setDate(yesterday.getDate()-1);
    const [deps, wds, bets, wins, newUsers, activeUsers, rounds] = await Promise.all([
      pool.query("SELECT COALESCE(SUM(amount),0) AS total, COUNT(*) AS count FROM transactions WHERE type='dep' AND status='success' AND created_at>=\$1", [today]),
      pool.query("SELECT COALESCE(SUM(ABS(amount)),0) AS total, COUNT(*) AS count FROM transactions WHERE type='wd' AND created_at>=\$1", [today]),
      pool.query("SELECT COALESCE(SUM(ABS(amount)),0) AS total, COUNT(*) AS count FROM transactions WHERE type='bet' AND created_at>=\$1", [today]),
      pool.query("SELECT COALESCE(SUM(amount),0) AS total, COUNT(*) AS count FROM transactions WHERE type='win' AND created_at>=\$1", [today]),
      pool.query("SELECT COUNT(*) AS count FROM users WHERE created_at>=\$1", [today]),
      pool.query("SELECT COUNT(DISTINCT user_id) AS count FROM game_bets WHERE created_at>=\$1", [today]),
      pool.query("SELECT COUNT(*) AS count FROM game_rounds WHERE created_at>=\$1", [today]),
    ]);
    const [ydeps, ywds, ybets, ywins] = await Promise.all([
      pool.query("SELECT COALESCE(SUM(amount),0) AS total FROM transactions WHERE type='dep' AND status='success' AND created_at>=\$1 AND created_at<\$2", [yesterday, today]),
      pool.query("SELECT COALESCE(SUM(ABS(amount)),0) AS total FROM transactions WHERE type='wd' AND created_at>=\$1 AND created_at<\$2", [yesterday, today]),
      pool.query("SELECT COALESCE(SUM(ABS(amount)),0) AS total FROM transactions WHERE type='bet' AND created_at>=\$1 AND created_at<\$2", [yesterday, today]),
      pool.query("SELECT COALESCE(SUM(amount),0) AS total FROM transactions WHERE type='win' AND created_at>=\$1 AND created_at<\$2", [yesterday, today]),
    ]);
    res.json({
      today: {
        deposits: parseFloat(deps.rows[0].total), depositCount: parseInt(deps.rows[0].count),
        withdrawals: parseFloat(wds.rows[0].total), withdrawalCount: parseInt(wds.rows[0].count),
        bets: parseFloat(bets.rows[0].total), betCount: parseInt(bets.rows[0].count),
        wins: parseFloat(wins.rows[0].total),
        profit: parseFloat(bets.rows[0].total) - parseFloat(wins.rows[0].total),
        newUsers: parseInt(newUsers.rows[0].count),
        activeUsers: parseInt(activeUsers.rows[0].count),
        rounds: parseInt(rounds.rows[0].count),
      },
      yesterday: {
        deposits: parseFloat(ydeps.rows[0].total),
        withdrawals: parseFloat(ywds.rows[0].total),
        bets: parseFloat(ybets.rows[0].total),
        wins: parseFloat(ywins.rows[0].total),
        profit: parseFloat(ybets.rows[0].total) - parseFloat(ywins.rows[0].total),
      }
    });
  } catch(err) { console.error(err); res.status(500).json({ error: "Failed to fetch daily report" }); }
});

app.get("/api/admin/reports/revenue", adminAuth, async (req, res) => {
  try {
    const days = parseInt(req.query.days) || 7;
    const rows = [];
    for (let i = days-1; i >= 0; i--) {
      const d = new Date(); d.setHours(0,0,0,0); d.setDate(d.getDate()-i);
      const next = new Date(d); next.setDate(next.getDate()+1);
      const [bets, wins, deps] = await Promise.all([
        pool.query("SELECT COALESCE(SUM(ABS(amount)),0) AS total FROM transactions WHERE type='bet' AND created_at>=\$1 AND created_at<\$2", [d, next]),
        pool.query("SELECT COALESCE(SUM(amount),0) AS total FROM transactions WHERE type='win' AND created_at>=\$1 AND created_at<\$2", [d, next]),
        pool.query("SELECT COALESCE(SUM(amount),0) AS total FROM transactions WHERE type='dep' AND status='success' AND created_at>=\$1 AND created_at<\$2", [d, next]),
      ]);
      rows.push({
        date: d.toISOString().split('T')[0],
        profit: parseFloat(bets.rows[0].total) - parseFloat(wins.rows[0].total),
        deposits: parseFloat(deps.rows[0].total),
        bets: parseFloat(bets.rows[0].total),
      });
    }
    res.json(rows);
  } catch(err) { res.status(500).json({ error: "Failed to fetch revenue" }); }
});

app.get("/api/admin/reports/topdepositors", adminAuth, async (req, res) => {
  try {
    const r = await pool.query("SELECT u.id, u.first_name, u.last_name, u.phone, COALESCE(SUM(t.amount),0) AS total_deposited, COUNT(t.id) AS deposit_count FROM users u LEFT JOIN transactions t ON t.user_id=u.id AND t.type='dep' AND t.status='success' GROUP BY u.id ORDER BY total_deposited DESC LIMIT 10");
    res.json(r.rows);
  } catch(err) { res.status(500).json({ error: "Failed" }); }
});

app.get("/api/admin/reports/topwinners", adminAuth, async (req, res) => {
  try {
    const r = await pool.query("SELECT u.id, u.first_name, u.last_name, COALESCE(SUM(CASE WHEN gb.cashed_out THEN gb.payout-gb.amount ELSE 0 END),0) AS total_profit, COUNT(gb.id) AS total_bets, COALESCE(MAX(gb.cashout_mult),0) AS best_mult FROM users u LEFT JOIN game_bets gb ON gb.user_id=u.id GROUP BY u.id ORDER BY total_profit DESC LIMIT 10");
    res.json(r.rows);
  } catch(err) { res.status(500).json({ error: "Failed" }); }
});

// ── GAME CONTROLS ──────────────────────────────────────────────────────────────
let gameConfig = { paused: false, minBet: 10, maxBet: 50000, bannerMsg: "" };

app.get("/api/admin/game/config", adminAuth, (req, res) => res.json(gameConfig));
app.get("/api/game/config", (req, res) => res.json({ paused: gameConfig.paused, bannerMsg: gameConfig.bannerMsg, minBet: gameConfig.minBet, maxBet: gameConfig.maxBet }));

app.post("/api/admin/game/pause", adminAuth, (req, res) => {
  gameConfig.paused = req.body.paused;
  io.emit("game:config", gameConfig);
  res.json({ ok: true, paused: gameConfig.paused });
});

app.post("/api/admin/game/limits", adminAuth, (req, res) => {
  const { minBet, maxBet } = req.body;
  if (minBet) gameConfig.minBet = parseFloat(minBet);
  if (maxBet) gameConfig.maxBet = parseFloat(maxBet);
  io.emit("game:config", gameConfig);
  res.json({ ok: true, config: gameConfig });
});

app.post("/api/admin/game/banner", adminAuth, (req, res) => {
  gameConfig.bannerMsg = req.body.message || "";
  io.emit("game:config", gameConfig);
  res.json({ ok: true, banner: gameConfig.bannerMsg });
});

// ── RISK MANAGEMENT ────────────────────────────────────────────────────────────
app.get("/api/admin/risk/suspicious", adminAuth, async (req, res) => {
  try {
    const r = await pool.query(`
      SELECT u.id, u.first_name, u.last_name, u.phone,
        COUNT(gb.id) AS total_bets,
        COUNT(CASE WHEN gb.cashed_out THEN 1 END) AS wins,
        ROUND(COUNT(CASE WHEN gb.cashed_out THEN 1 END)::numeric/NULLIF(COUNT(gb.id),0)*100,1) AS win_rate,
        COALESCE(AVG(CASE WHEN gb.cashed_out THEN gb.cashout_mult END),0) AS avg_cashout,
        COALESCE(MAX(gb.cashout_mult),0) AS max_cashout,
        COALESCE(SUM(CASE WHEN gb.cashed_out THEN gb.payout-gb.amount ELSE 0 END),0) AS total_profit
      FROM users u
      LEFT JOIN game_bets gb ON gb.user_id=u.id
      GROUP BY u.id
      HAVING COUNT(gb.id) >= 10
      ORDER BY win_rate DESC NULLS LAST
      LIMIT 20
    `);
    res.json(r.rows);
  } catch(err) { res.status(500).json({ error: "Failed" }); }
});

app.get("/api/admin/risk/largewithdrawals", adminAuth, async (req, res) => {
  try {
    const r = await pool.query(`
      SELECT t.*, u.first_name, u.last_name, u.phone
      FROM transactions t
      LEFT JOIN users u ON u.id=t.user_id
      WHERE t.type='wd' AND ABS(t.amount) >= 1000
      ORDER BY t.created_at DESC LIMIT 50
    `);
    res.json(r.rows);
  } catch(err) { res.status(500).json({ error: "Failed" }); }
});

// ── COMMUNICATIONS ─────────────────────────────────────────────────────────────
app.post("/api/admin/notify/:userId", adminAuth, async (req, res) => {
  const { message } = req.body;
  if (!message) return res.status(400).json({ error: "Message required" });
  try {
    const u = await pool.query("SELECT * FROM users WHERE id=\$1", [req.params.userId]);
    if (!u.rows.length) return res.status(404).json({ error: "User not found" });
    const sockets = [...socketUsers.entries()].filter(([,uid]) => uid === parseInt(req.params.userId));
    sockets.forEach(([sid]) => {
      const sock = io.sockets.sockets.get(sid);
      if (sock) sock.emit("admin:notify", { message, time: new Date() });
    });
    res.json({ ok: true, delivered: sockets.length > 0, message });
  } catch(err) { res.status(500).json({ error: "Failed" }); }
});

app.post("/api/admin/broadcast", adminAuth, async (req, res) => {
  const { message } = req.body;
  if (!message) return res.status(400).json({ error: "Message required" });
  io.emit("admin:broadcast", { message, time: new Date() });
  res.json({ ok: true, message });
});

const PORT = process.env.PORT || 3001;
initDB()
  .then(()=>backfillAviIds()).then(()=>{startWaiting();server.listen(PORT,()=>console.log(`Server running on port ${PORT}`));})
  .catch(err=>{console.error("DB init failed:",err);process.exit(1);});
