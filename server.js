// The Hunt For Numbers — сайт прокрутки номеров
// Вход через Roblox (OAuth 2.0 + PKCE), рубли берутся из игры, номера выводятся в игру.
const path = require("path");
const crypto = require("crypto");
const express = require("express");
const cookieSession = require("cookie-session");
const { Pool } = require("pg");
const P = require("./plates");

const {
  PORT = 3000,
  DATABASE_URL,
  ROBLOX_CLIENT_ID,
  ROBLOX_CLIENT_SECRET,
  SESSION_SECRET = "dev-secret-change-me",
  GAME_SECRET,
  PUBLIC_URL = "http://localhost:3000",
  GAME_URL = "https://www.roblox.com/games/",
} = process.env;

const ROLL_COST = Number(process.env.ROLL_COST || 500); // как в игре
const ONLINE_WINDOW_SEC = 25; // игрок «в игре», если сервер присылал его баланс за последние N секунд
const REDELIVER_SEC = 90; // номер «в пути» без ответа от игры дольше — отправляем ещё раз
const REDIRECT_URI = PUBLIC_URL.replace(/\/$/, "") + "/auth/callback";

if (!DATABASE_URL) {
  console.error("Нет DATABASE_URL");
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: /localhost|127\.0\.0\.1/.test(DATABASE_URL) ? false : { rejectUnauthorized: false },
  max: 5,
});

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      user_id      BIGINT PRIMARY KEY,
      username     TEXT,
      display_name TEXT,
      avatar       TEXT,
      balance      BIGINT,            -- последний баланс из игры (NULL — ещё ни разу не заходил в игру)
      last_charge  BIGINT NOT NULL DEFAULT 0, -- id последнего списания, которое игра уже применила
      last_sync    TIMESTAMPTZ,
      online       BOOLEAN NOT NULL DEFAULT FALSE,
      created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS charges (
      id         BIGSERIAL PRIMARY KEY,
      user_id    BIGINT NOT NULL,
      amount     BIGINT NOT NULL,       -- >0 списать рубли в игре, <0 начислить
      reason     TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS charges_user_idx ON charges (user_id, id);
    CREATE TABLE IF NOT EXISTS plates (
      id          BIGSERIAL PRIMARY KEY,
      user_id     BIGINT NOT NULL,
      country     TEXT NOT NULL,
      plate       TEXT NOT NULL,
      norm        TEXT NOT NULL,
      tier        INT NOT NULL,
      sell_price  INT NOT NULL,
      status      TEXT NOT NULL DEFAULT 'site', -- site | pending | delivering | delivered | failed | sold
      note        TEXT,
      created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS plates_user_idx ON plates (user_id, status);
    CREATE UNIQUE INDEX IF NOT EXISTS plates_norm_active
      ON plates (norm) WHERE status IN ('site','pending','delivering');
  `);
}

const app = express();
app.set("trust proxy", 1);
app.use(express.json({ limit: "256kb" }));
app.use(
  cookieSession({
    name: "hunt",
    keys: [SESSION_SECRET],
    maxAge: 30 * 24 * 3600 * 1000,
    sameSite: "lax",
    secure: PUBLIC_URL.startsWith("https"),
    httpOnly: true,
  })
);

// ---------- Вход через Roblox ----------
const b64url = (buf) => buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

app.get("/auth/login", (req, res) => {
  if (!ROBLOX_CLIENT_ID) return res.status(500).send("ROBLOX_CLIENT_ID не задан");
  const verifier = b64url(crypto.randomBytes(48));
  const challenge = b64url(crypto.createHash("sha256").update(verifier).digest());
  const state = b64url(crypto.randomBytes(16));
  req.session.oauth = { verifier, state };
  const q = new URLSearchParams({
    client_id: ROBLOX_CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    scope: "openid profile",
    response_type: "code",
    state,
    code_challenge: challenge,
    code_challenge_method: "S256",
  });
  res.redirect("https://apis.roblox.com/oauth/v1/authorize?" + q.toString());
});

app.get("/auth/callback", async (req, res) => {
  try {
    const o = req.session.oauth;
    if (!o || !req.query.code || req.query.state !== o.state) {
      return res.redirect("/?error=state");
    }
    req.session.oauth = null;
    const tokenRes = await fetch("https://apis.roblox.com/oauth/v1/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: ROBLOX_CLIENT_ID,
        client_secret: ROBLOX_CLIENT_SECRET || "",
        grant_type: "authorization_code",
        code: String(req.query.code),
        code_verifier: o.verifier,
        redirect_uri: REDIRECT_URI,
      }),
    });
    const token = await tokenRes.json();
    if (!tokenRes.ok || !token.access_token) {
      console.error("token error", token);
      return res.redirect("/?error=token");
    }
    const infoRes = await fetch("https://apis.roblox.com/oauth/v1/userinfo", {
      headers: { Authorization: "Bearer " + token.access_token },
    });
    const info = await infoRes.json();
    if (!info.sub) return res.redirect("/?error=userinfo");
    await pool.query(
      `INSERT INTO users (user_id, username, display_name, avatar) VALUES ($1,$2,$3,$4)
       ON CONFLICT (user_id) DO UPDATE SET username=$2, display_name=$3, avatar=COALESCE($4, users.avatar)`,
      [info.sub, info.preferred_username || null, info.name || info.nickname || null, info.picture || null]
    );
    req.session.uid = String(info.sub);
    res.redirect("/");
  } catch (e) {
    console.error(e);
    res.redirect("/?error=auth");
  }
});

// Только для локальной проверки (DEV_LOGIN=1), на хостинге выключено
if (process.env.DEV_LOGIN === "1" && process.env.NODE_ENV !== "production") {
  app.get("/auth/dev/:uid", async (req, res) => {
    await pool.query(
      `INSERT INTO users (user_id, username, display_name) VALUES ($1,'dev','Dev') ON CONFLICT DO NOTHING`,
      [req.params.uid]
    );
    req.session.uid = req.params.uid;
    res.redirect("/");
  });
}

app.post("/auth/logout", (req, res) => {
  req.session = null;
  res.json({ ok: true });
});

// ---------- API игрока ----------
function auth(req, res, next) {
  if (!req.session || !req.session.uid) return res.status(401).json({ error: "Войдите через Roblox" });
  req.uid = req.session.uid;
  next();
}

async function availableFor(client, uid, lock) {
  const u = (
    await client.query(`SELECT * FROM users WHERE user_id=$1 ${lock ? "FOR UPDATE" : ""}`, [uid])
  ).rows[0];
  if (!u) return { user: null, available: null };
  if (u.balance === null) return { user: u, available: null };
  const pending = (
    await client.query(`SELECT COALESCE(SUM(amount),0) AS s FROM charges WHERE user_id=$1 AND id>$2`, [uid, u.last_charge])
  ).rows[0].s;
  return { user: u, available: Math.max(0, Number(u.balance) - Number(pending)) };
}

function isOnline(u) {
  return !!(u && u.online && u.last_sync && Date.now() - new Date(u.last_sync).getTime() < ONLINE_WINDOW_SEC * 1000);
}

function plateOut(p) {
  const r = P.RARITIES[p.tier];
  return {
    id: String(p.id),
    country: p.country,
    plate: p.plate,
    tier: p.tier,
    rarity: r.name,
    color: r.color,
    sellPrice: p.sell_price,
    status: p.status,
    note: p.note,
    createdAt: p.created_at,
  };
}

app.get("/api/config", (req, res) => {
  res.json({ rollCost: ROLL_COST, countries: P.COUNTRIES, sellRanges: P.SELL_RANGES, gameUrl: GAME_URL });
});

app.get("/api/me", async (req, res) => {
  if (!req.session || !req.session.uid) return res.json({ user: null });
  const { user, available } = await availableFor(pool, req.session.uid, false);
  if (!user) {
    req.session = null;
    return res.json({ user: null });
  }
  res.json({
    user: {
      id: String(user.user_id),
      username: user.username,
      displayName: user.display_name,
      avatar: user.avatar,
    },
    balance: available,
    synced: user.balance !== null,
    online: isOnline(user),
  });
});

const lastRollAt = new Map();

app.post("/api/roll", auth, async (req, res) => {
  const country = P.COUNTRIES.includes(req.body && req.body.country) ? req.body.country : "RUS";
  const now = Date.now();
  if (now - (lastRollAt.get(req.uid) || 0) < 700) return res.status(429).json({ error: "Слишком быстро" });
  lastRollAt.set(req.uid, now);

  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const { user, available } = await availableFor(client, req.uid, true);
    if (!user) throw Object.assign(new Error("Нет пользователя"), { status: 401 });
    if (available === null) {
      throw Object.assign(new Error("Зайдите в игру хотя бы раз — так сайт узнает ваш баланс рублей"), { status: 409 });
    }
    if (available < ROLL_COST) {
      throw Object.assign(new Error("Недостаточно рублей! Прокрутка стоит " + ROLL_COST + " ₽"), { status: 402 });
    }
    let row = null;
    for (let i = 0; i < 10 && !row; i++) {
      const plate = P.generatePlate(country);
      const rarity = P.getRarity(country, plate);
      const sell = P.getSellPrice(rarity.tier);
      const r = await client.query(
        `INSERT INTO plates (user_id, country, plate, norm, tier, sell_price) VALUES ($1,$2,$3,$4,$5,$6)
         ON CONFLICT DO NOTHING RETURNING *`,
        [req.uid, country, plate, P.normalizePlate(plate), rarity.tier, sell]
      );
      row = r.rows[0] || null;
    }
    if (!row) throw Object.assign(new Error("Не удалось подобрать свободный номер, попробуйте ещё раз"), { status: 503 });
    await client.query(`INSERT INTO charges (user_id, amount, reason) VALUES ($1,$2,$3)`, [
      req.uid,
      ROLL_COST,
      "roll:" + row.id,
    ]);
    await client.query("COMMIT");
    res.json({ plate: plateOut(row), balance: available - ROLL_COST });
  } catch (e) {
    await client.query("ROLLBACK").catch(() => {});
    if (!e.status) console.error(e);
    res.status(e.status || 500).json({ error: e.status ? e.message : "Ошибка сервера" });
  } finally {
    client.release();
  }
});

app.get("/api/plates", auth, async (req, res) => {
  const active = await pool.query(
    `SELECT * FROM plates WHERE user_id=$1 AND status IN ('site','pending','delivering') ORDER BY tier DESC, id DESC`,
    [req.uid]
  );
  const history = await pool.query(
    `SELECT * FROM plates WHERE user_id=$1 AND status IN ('delivered','failed','sold')
     ORDER BY updated_at DESC LIMIT 30`,
    [req.uid]
  );
  res.json({ plates: active.rows.map(plateOut), history: history.rows.map(plateOut) });
});

async function changePlate(req, res, from, to) {
  const r = await pool.query(
    `UPDATE plates SET status=$1, updated_at=now() WHERE id=$2 AND user_id=$3 AND status=$4 RETURNING *`,
    [to, req.params.id, req.uid, from]
  );
  if (!r.rows[0]) return res.status(409).json({ error: "Номер уже недоступен для этого действия" });
  res.json({ plate: plateOut(r.rows[0]) });
}

app.post("/api/plates/:id/withdraw", auth, (req, res) => changePlate(req, res, "site", "pending"));
app.post("/api/plates/:id/cancel", auth, (req, res) => changePlate(req, res, "pending", "site"));

app.post("/api/plates/:id/sell", auth, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const r = await client.query(
      `UPDATE plates SET status='sold', updated_at=now() WHERE id=$1 AND user_id=$2 AND status='site' RETURNING *`,
      [req.params.id, req.uid]
    );
    const p = r.rows[0];
    if (!p) throw Object.assign(new Error("Номер уже недоступен"), { status: 409 });
    await client.query(`INSERT INTO charges (user_id, amount, reason) VALUES ($1,$2,$3)`, [
      req.uid,
      -p.sell_price,
      "sell:" + p.id,
    ]);
    await client.query("COMMIT");
    const { available } = await availableFor(pool, req.uid, false);
    res.json({ plate: plateOut(p), balance: available });
  } catch (e) {
    await client.query("ROLLBACK").catch(() => {});
    res.status(e.status || 500).json({ error: e.status ? e.message : "Ошибка сервера" });
  } finally {
    client.release();
  }
});

// ---------- API для игровых серверов ----------
function gameAuth(req, res, next) {
  const got = String(req.get("x-game-secret") || "");
  if (!GAME_SECRET || got.length !== GAME_SECRET.length ||
      !crypto.timingSafeEqual(Buffer.from(got), Buffer.from(GAME_SECRET))) {
    return res.status(403).json({ error: "bad secret" });
  }
  next();
}

// Игра присылает баланс игроков на сервере, получает новые списания и номера к выдаче.
// body: { players: [{userId, name, displayName, balance, lastCharge}], left: [{userId, balance, lastCharge}] }
app.post("/api/game/sync", gameAuth, async (req, res) => {
  const players = Array.isArray(req.body.players) ? req.body.players.slice(0, 200) : [];
  const left = Array.isArray(req.body.left) ? req.body.left.slice(0, 200) : [];
  const client = await pool.connect();
  try {
    const save = async (p, online) => {
      const uid = String(Math.floor(Number(p.userId)));
      const bal = Math.max(0, Math.floor(Number(p.balance)));
      const lc = Math.max(0, Math.floor(Number(p.lastCharge) || 0));
      if (!/^\d+$/.test(uid) || !Number.isFinite(bal)) return null;
      await client.query(
        `INSERT INTO users (user_id, username, display_name, balance, last_charge, last_sync, online)
         VALUES ($1,$2,$3,$4,$5,now(),$6)
         ON CONFLICT (user_id) DO UPDATE SET balance=$4, last_charge=GREATEST(users.last_charge,$5),
           last_sync=now(), online=$6, username=COALESCE($2, users.username),
           display_name=COALESCE(users.display_name, $3)`,
        [uid, p.name || null, p.displayName || null, bal, lc, online]
      );
      return uid;
    };
    const ids = [];
    for (const p of players) {
      const uid = await save(p, true);
      if (uid) ids.push(uid);
    }
    for (const p of left) await save(p, false);

    let charges = [];
    let plates = [];
    if (ids.length) {
      charges = (
        await client.query(
          `SELECT c.id, c.user_id, c.amount, c.reason FROM charges c JOIN users u ON u.user_id=c.user_id
           WHERE c.user_id = ANY($1::bigint[]) AND c.id > u.last_charge ORDER BY c.id`,
          [ids]
        )
      ).rows.map((c) => ({ id: Number(c.id), userId: Number(c.user_id), amount: Number(c.amount), reason: c.reason }));
      plates = (
        await client.query(
          `UPDATE plates SET status='delivering', updated_at=now()
           WHERE user_id = ANY($1::bigint[])
             AND (status='pending' OR (status='delivering' AND updated_at < now() - ($2 || ' seconds')::interval))
           RETURNING *`,
          [ids, String(REDELIVER_SEC)]
        )
      ).rows.map((p) => ({
        id: Number(p.id),
        userId: Number(p.user_id),
        country: p.country,
        plate: p.plate,
        tier: p.tier,
        sellPrice: p.sell_price,
      }));
    }
    res.json({ charges, plates });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "db" });
  } finally {
    client.release();
  }
});

// Ответ игры по выданным номерам: body { results: [{id, ok, reason}] }
app.post("/api/game/plates-ack", gameAuth, async (req, res) => {
  const results = Array.isArray(req.body.results) ? req.body.results.slice(0, 500) : [];
  const client = await pool.connect();
  try {
    for (const r of results) {
      await client.query("BEGIN");
      if (r.ok) {
        await client.query(
          `UPDATE plates SET status='delivered', note=NULL, updated_at=now() WHERE id=$1 AND status='delivering'`,
          [r.id]
        );
      } else {
        // номер занят в игре другим игроком — возвращаем его стоимость рублями
        const p = (
          await client.query(
            `UPDATE plates SET status='failed', note=$2, updated_at=now() WHERE id=$1 AND status='delivering' RETURNING *`,
            [r.id, String(r.reason || "Не удалось выдать номер").slice(0, 200)]
          )
        ).rows[0];
        if (p) {
          await client.query(`INSERT INTO charges (user_id, amount, reason) VALUES ($1,$2,$3)`, [
            p.user_id,
            -Math.max(p.sell_price, ROLL_COST),
            "refund:" + p.id,
          ]);
        }
      }
      await client.query("COMMIT");
    }
    res.json({ ok: true });
  } catch (e) {
    await client.query("ROLLBACK").catch(() => {});
    console.error(e);
    res.status(500).json({ error: "db" });
  } finally {
    client.release();
  }
});

app.get("/healthz", (req, res) => res.send("ok"));
app.use(express.static(path.join(__dirname, "public"), { maxAge: "5m" }));

initDb()
  .then(() => app.listen(PORT, () => console.log("Сайт запущен на порту " + PORT)))
  .catch((e) => {
    console.error("DB init failed", e);
    process.exit(1);
  });
