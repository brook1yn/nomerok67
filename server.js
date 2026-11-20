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
  GAME_URL = "https://www.roblox.com/games/",
} = process.env;

const ROLL_COST = Number(process.env.ROLL_COST || 500); // как в игре
const ONLINE_WINDOW_SEC = 25; // игрок «в игре», если сервер присылал его баланс за последние N секунд
const REDELIVER_SEC = 90; // номер «в пути» без ответа от игры дольше — отправляем ещё раз
// Адрес сайта: из PUBLIC_URL, а если не задан — берём из запроса (Render отдаёт https и свой домен)
const PUBLIC_URL = String(process.env.PUBLIC_URL || "")
  .trim()
  .replace(/\/auth\/callback\/?$/, "")
  .replace(/\/+$/, "");
function redirectUri(req) {
  const base = PUBLIC_URL || req.protocol + "://" + req.get("host");
  return base + "/auth/callback";
}

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
    ALTER TABLE plates ADD COLUMN IF NOT EXISTS source TEXT NOT NULL DEFAULT 'roll';
    CREATE TABLE IF NOT EXISTS cars (
      id         BIGSERIAL PRIMARY KEY,
      user_id    BIGINT NOT NULL,
      car_id     TEXT NOT NULL,
      car_name   TEXT NOT NULL,
      paid       INT NOT NULL DEFAULT 0,
      source     TEXT NOT NULL,
      status     TEXT NOT NULL DEFAULT 'site', -- site | pending | delivering | delivered | failed
      note       TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS cars_user_idx ON cars (user_id, status);
    CREATE INDEX IF NOT EXISTS plates_feed_idx ON plates (id DESC);
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
    secure: process.env.NODE_ENV === "production",
    httpOnly: true,
  })
);

// ---------- Вход через Roblox ----------
// Права приложения: по умолчанию "openid profile". Их нужно отметить в настройках OAuth-приложения Roblox.
const OAUTH_SCOPES = String(process.env.ROBLOX_SCOPES || "openid profile").trim();

async function robloxPublicProfile(uid) {
  const out = { username: null, displayName: null, avatar: null };
  try {
    const u = await (await fetch("https://users.roblox.com/v1/users/" + uid)).json();
    out.username = u.name || null;
    out.displayName = u.displayName || null;
  } catch {}
  try {
    const t = await (
      await fetch("https://thumbnails.roblox.com/v1/users/avatar-headshot?size=150x150&format=Png&userIds=" + uid)
    ).json();
    out.avatar = (t.data && t.data[0] && t.data[0].imageUrl) || null;
  } catch {}
  return out;
}
const b64url = (buf) => buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

app.get("/auth/login", (req, res) => {
  if (!ROBLOX_CLIENT_ID) return res.status(500).send("ROBLOX_CLIENT_ID не задан");
  const verifier = b64url(crypto.randomBytes(48));
  const challenge = b64url(crypto.createHash("sha256").update(verifier).digest());
  const state = b64url(crypto.randomBytes(16));
  req.session.oauth = { verifier, state };
  const q = new URLSearchParams({
    client_id: ROBLOX_CLIENT_ID,
    redirect_uri: redirectUri(req),
    scope: OAUTH_SCOPES,
    response_type: "code",
    state,
    code_challenge: challenge,
    code_challenge_method: "S256",
  });
  res.redirect("https://apis.roblox.com/oauth/v1/authorize?" + q.toString());
});

// Подсказка: какой Redirect URL вписать в OAuth-приложение Roblox
app.get("/auth/where", (req, res) => {
  res.type("text/plain; charset=utf-8").send(
    "Впишите в Roblox (OAuth App → Redirect URLs) ровно эту строку:\n\n" + redirectUri(req) + "\n"
  );
});

app.get("/auth/callback", async (req, res) => {
  try {
    const o = req.session.oauth;
    if (req.query.error) {
      console.error("oauth error", req.query.error, req.query.error_description);
      return res.redirect("/?error=" + encodeURIComponent(String(req.query.error)));
    }
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
        redirect_uri: redirectUri(req),
      }),
    });
    const token = await tokenRes.json();
    if (!tokenRes.ok || !token.access_token) {
      console.error("token error", token);
      return res.redirect("/?error=token");
    }
    // кто вошёл: userinfo (нужен openid), запасной путь — introspect токена
    let info = {};
    try {
      const infoRes = await fetch("https://apis.roblox.com/oauth/v1/userinfo", {
        headers: { Authorization: "Bearer " + token.access_token },
      });
      info = await infoRes.json();
    } catch {}
    if (!info.sub) {
      const intr = await (
        await fetch("https://apis.roblox.com/oauth/v1/token/introspect", {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({
            token: token.access_token,
            client_id: ROBLOX_CLIENT_ID,
            client_secret: ROBLOX_CLIENT_SECRET || "",
          }),
        })
      ).json();
      if (!intr.sub) {
        console.error("no sub", info, intr);
        return res.redirect("/?error=userinfo");
      }
      info = { sub: intr.sub };
    }
    if (!/^\d+$/.test(String(info.sub))) return res.redirect("/?error=userinfo");
    if (!info.preferred_username || !info.picture) {
      const pub = await robloxPublicProfile(info.sub);
      info.preferred_username = info.preferred_username || pub.username;
      info.name = info.name || pub.displayName;
      info.picture = info.picture || pub.avatar;
    }
    await pool.query(
      `INSERT INTO users (user_id, username, display_name, avatar) VALUES ($1,$2,$3,$4)
       ON CONFLICT (user_id) DO UPDATE SET username=COALESCE($2, users.username),
         display_name=COALESCE($3, users.display_name), avatar=COALESCE($4, users.avatar)`,
      [String(info.sub), info.preferred_username || null, info.name || info.nickname || null, info.picture || null]
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
    source: p.source,
    note: p.note,
    createdAt: p.created_at,
  };
}

// ---------- Кейсы ----------
// weights: шанс редкости номера 1..6 (в процентах).
// cars: машины из игры (только не донатные), chance — в процентах. Если машина не выпала — выпадает номер по weights.
// id машины = атрибут CarId шаблона в ServerStorage.CarTemplates.
const CARS = {
  LadaPriora: { name: "Lada Priora", value: 500000, color: "rgb(70,160,255)", image: "/cars/priora.webp" },
  "drift  car supra": { name: "Toyota Supra (дрифт)", value: 5000000, color: "rgb(176,110,255)", image: "/cars/supra.webp" },
  BMWM5F90: { name: "BMW M5 F90", value: 15000000, color: "rgb(255,196,56)", image: "/cars/bmw-m5-f90.webp" },
  Gelik: { name: "Mercedes-Benz G63", value: 20000000, color: "rgb(255,84,112)", image: "/cars/gelik.webp" },
};
const CASES = [
  { id: "start", name: "Стартовый", price: 600, color: "rgb(86,214,120)", weights: [0, 60, 30, 8, 1.9, 0.1, 0] },
  { id: "rare", name: "Редкий", price: 2000, color: "rgb(70,160,255)", weights: [0, 0, 40, 45, 14.88, 0.1, 0.02] },
  { id: "elite", name: "Элитный", price: 4500, color: "rgb(176,110,255)", weights: [0, 0, 0, 30, 69.88, 0.1, 0.02] },
  {
    id: "auto", name: "Автокейс", price: 10000, color: "rgb(255,150,60)", kind: "cars", cover: ["LadaPriora", "drift  car supra"],
    weights: [0, 0, 45, 45, 9.9, 0.1, 0],
    cars: [
      { id: "LadaPriora", chance: 0.5 },
      { id: "drift  car supra", chance: 0.05 },
      { id: "BMWM5F90", chance: 0.01 },
      { id: "Gelik", chance: 0.005 },
    ],
  },
  {
    id: "garage", name: "Премиум-гараж", price: 50000, color: "rgb(255,84,112)", kind: "cars", cover: ["Gelik", "BMWM5F90"],
    weights: [0, 0, 0, 50, 49.9, 0.1, 0],
    cars: [
      { id: "LadaPriora", chance: 2 },
      { id: "drift  car supra", chance: 0.25 },
      { id: "BMWM5F90", chance: 0.08 },
      { id: "Gelik", chance: 0.03 },
    ],
  },
];
for (const cs of CASES) {
  for (const c of cs.cars || []) Object.assign(c, CARS[c.id]);
  if (cs.cover) cs.coverImages = cs.cover.map((id) => CARS[id].image);
}

// машина из кейса: случайное число 0..100, идём по шансам машин
function pickCar(cs) {
  if (!cs.cars) return null;
  let r = crypto.randomInt(0, 10000000) / 100000; // 0..100 с точностью 0.00001
  if (process.env.DEV_LOGIN === "1" && process.env.DEV_CARS) r /= Number(process.env.DEV_CARS); // только локальная проверка
  for (const c of cs.cars) {
    r -= c.chance;
    if (r < 0) return c;
  }
  return null;
}
function carOut(c) {
  const def = CARS[c.car_id] || { color: "rgb(150,156,172)", value: 0 };
  return { id: String(c.id), kind: "car", carId: c.car_id, name: c.car_name, color: def.color, value: def.value, image: def.image || null, status: c.status, note: c.note, source: c.source };
}
const UPGRADE_EDGE = 0.85; // шанс апгрейда = стоимость ставки / стоимость цели × 0.85
const UPGRADE_MAX_CHANCE = 0.75;
const UPGRADE_MAX_ITEMS = 6;

function pickTier(weights) {
  const total = weights.reduce((a, b) => a + b, 0);
  let r = (crypto.randomInt(0, 1000000) / 1000000) * total;
  for (let t = 1; t < weights.length; t++) {
    r -= weights[t];
    if (r < 0) return t;
  }
  return weights.length - 1;
}

// Вставить новый номер нужной редкости (уникальный среди активных номеров сайта)
async function insertPlateOfTier(client, uid, tier, source) {
  for (let i = 0; i < 8; i++) {
    const g = P.generateWithTier(tier);
    if (!g) continue;
    const r = await client.query(
      `INSERT INTO plates (user_id, country, plate, norm, tier, sell_price, source) VALUES ($1,$2,$3,$4,$5,$6,$7)
       ON CONFLICT DO NOTHING RETURNING *`,
      [uid, g.country, g.plate, P.normalizePlate(g.plate), tier, P.getSellPrice(tier), source]
    );
    if (r.rows[0]) return r.rows[0];
  }
  return null;
}

function httpErr(status, message) {
  return Object.assign(new Error(message), { status });
}

async function withTx(res, fn) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const out = await fn(client);
    await client.query("COMMIT");
    res.json(out);
  } catch (e) {
    await client.query("ROLLBACK").catch(() => {});
    if (!e.status) console.error(e);
    res.status(e.status || 500).json({ error: e.status ? e.message : "Ошибка сервера" });
  } finally {
    client.release();
  }
}

app.get("/api/config", (req, res) => {
  res.json({
    rollCost: ROLL_COST,
    countries: P.COUNTRIES,
    sellRanges: P.SELL_RANGES,
    sellMid: P.SELL_MID,
    rarities: P.RARITIES,
    gameUrl: GAME_URL,
    cases: CASES,
    upgrade: { edge: UPGRADE_EDGE, maxChance: UPGRADE_MAX_CHANCE, maxItems: UPGRADE_MAX_ITEMS },
  });
});

// ---------- Онлайн и лента ----------
const visitors = new Map(); // id посетителя -> время последнего запроса
const ONLINE_SITE_SEC = 30;
setInterval(() => {
  const cut = Date.now() - ONLINE_SITE_SEC * 1000;
  for (const [k, t] of visitors) if (t < cut) visitors.delete(k);
}, 15000).unref();

app.get("/api/live", async (req, res) => {
  if (!req.session.vid) req.session.vid = b64url(crypto.randomBytes(9));
  visitors.set(req.session.vid, Date.now());
  const since = Math.max(0, Number(req.query.since) || 0);
  const sinceCar = Math.max(0, Number(req.query.sincec) || 0);
  // задержка 5 сек — чтобы лента не спойлерила результат, пока у игрока крутится анимация
  const rows = (
    await pool.query(
      `SELECT p.id, p.country, p.plate, p.tier, p.source, p.created_at, u.username, u.display_name, u.avatar
       FROM plates p JOIN users u ON u.user_id = p.user_id
       WHERE p.id > $1 AND p.created_at < now() - interval '5 seconds'
       ORDER BY p.id DESC LIMIT 30`,
      [since]
    )
  ).rows;
  const carRows = (
    await pool.query(
      `SELECT c.id, c.car_id, c.car_name, c.source, c.created_at, u.username, u.display_name, u.avatar
       FROM cars c JOIN users u ON u.user_id = c.user_id
       WHERE c.id > $1 AND c.created_at < now() - interval '6 seconds'
       ORDER BY c.id DESC LIMIT 10`,
      [sinceCar]
    )
  ).rows;
  res.json({
    online: visitors.size,
    feed: rows.map((r) => ({
      id: Number(r.id),
      country: r.country,
      plate: r.plate,
      tier: r.tier,
      rarity: P.RARITIES[r.tier].name,
      color: P.RARITIES[r.tier].color,
      source: r.source,
      user: r.display_name || r.username || "Игрок",
      avatar: r.avatar,
      t: new Date(r.created_at).getTime(),
    })),
    cars: carRows.map((r) => ({
      id: Number(r.id),
      kind: "car",
      carId: r.car_id,
      name: r.car_name,
      color: (CARS[r.car_id] || {}).color || "rgb(255,196,56)",
      image: (CARS[r.car_id] || {}).image || null,
      source: r.source,
      user: r.display_name || r.username || "Игрок",
      avatar: r.avatar,
      t: new Date(r.created_at).getTime(),
    })),
  });
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
    `SELECT * FROM plates WHERE user_id=$1 AND status IN ('delivered','failed','sold','upgraded')
     ORDER BY updated_at DESC LIMIT 30`,
    [req.uid]
  );
  const carsActive = await pool.query(
    `SELECT * FROM cars WHERE user_id=$1 AND status IN ('site','pending','delivering') ORDER BY id DESC`,
    [req.uid]
  );
  const carsHistory = await pool.query(
    `SELECT * FROM cars WHERE user_id=$1 AND status IN ('delivered','failed') ORDER BY updated_at DESC LIMIT 15`,
    [req.uid]
  );
  res.json({
    plates: active.rows.map(plateOut),
    history: history.rows.map(plateOut),
    cars: carsActive.rows.map(carOut),
    carHistory: carsHistory.rows.map(carOut),
  });
});

async function changePlate(req, res, from, to) {
  const r = await pool.query(
    `UPDATE plates SET status=$1, updated_at=now() WHERE id=$2 AND user_id=$3 AND status=$4 RETURNING *`,
    [to, req.params.id, req.uid, from]
  );
  if (!r.rows[0]) return res.status(409).json({ error: "Номер уже недоступен для этого действия" });
  res.json({ plate: plateOut(r.rows[0]) });
}

async function changeCar(req, res, from, to) {
  const r = await pool.query(
    `UPDATE cars SET status=$1, updated_at=now() WHERE id=$2 AND user_id=$3 AND status=$4 RETURNING *`,
    [to, req.params.id, req.uid, from]
  );
  if (!r.rows[0]) return res.status(409).json({ error: "Машина уже недоступна для этого действия" });
  res.json({ car: carOut(r.rows[0]) });
}
app.post("/api/cars/:id/withdraw", auth, (req, res) => changeCar(req, res, "site", "pending"));
app.post("/api/cars/:id/cancel", auth, (req, res) => changeCar(req, res, "pending", "site"));

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

app.post("/api/case/:id/open", auth, (req, res) => {
  const cs = CASES.find((c) => c.id === req.params.id);
  if (!cs) return res.status(404).json({ error: "Нет такого кейса" });
  const now = Date.now();
  if (now - (lastRollAt.get(req.uid) || 0) < 700) return res.status(429).json({ error: "Слишком быстро" });
  lastRollAt.set(req.uid, now);
  withTx(res, async (client) => {
    const { user, available } = await availableFor(client, req.uid, true);
    if (!user) throw httpErr(401, "Нет пользователя");
    if (available === null) throw httpErr(409, "Зайдите в игру хотя бы раз — так сайт узнает ваш баланс рублей");
    if (available < cs.price) throw httpErr(402, "Недостаточно рублей! Кейс стоит " + cs.price + " ₽");
    const car = pickCar(cs);
    if (car) {
      const c = (
        await client.query(
          `INSERT INTO cars (user_id, car_id, car_name, paid, source) VALUES ($1,$2,$3,$4,$5) RETURNING *`,
          [req.uid, car.id, car.name, cs.price, "case:" + cs.id]
        )
      ).rows[0];
      await client.query(`INSERT INTO charges (user_id, amount, reason) VALUES ($1,$2,$3)`, [
        req.uid,
        cs.price,
        "case:" + cs.id + ":car" + c.id,
      ]);
      return { car: carOut(c), balance: available - cs.price };
    }
    const tier = pickTier(cs.weights);
    const row = await insertPlateOfTier(client, req.uid, tier, "case:" + cs.id);
    if (!row) throw httpErr(503, "Не удалось подобрать номер, попробуйте ещё раз");
    await client.query(`INSERT INTO charges (user_id, amount, reason) VALUES ($1,$2,$3)`, [
      req.uid,
      cs.price,
      "case:" + cs.id + ":" + row.id,
    ]);
    return { plate: plateOut(row), balance: available - cs.price };
  });
});

// Апгрейд: ставим 1–6 своих номеров, выбираем редкость-цель. Победа — новый номер этой редкости,
// проигрыш — номера сгорают. Шанс = сумма цен / средняя цена цели × 0.85 (максимум 75%).
app.post("/api/upgrade", auth, (req, res) => {
  const ids = [...new Set((Array.isArray(req.body.plateIds) ? req.body.plateIds : []).map(String))].filter((x) => /^\d+$/.test(x));
  const target = Math.floor(Number(req.body.targetTier));
  if (!ids.length || ids.length > UPGRADE_MAX_ITEMS) return res.status(400).json({ error: "Выберите от 1 до " + UPGRADE_MAX_ITEMS + " номеров" });
  if (!(target >= 2 && target <= 6)) return res.status(400).json({ error: "Выберите редкость" });
  const now = Date.now();
  if (now - (lastRollAt.get(req.uid) || 0) < 700) return res.status(429).json({ error: "Слишком быстро" });
  lastRollAt.set(req.uid, now);
  withTx(res, async (client) => {
    const rows = (
      await client.query(`SELECT * FROM plates WHERE id = ANY($1::bigint[]) AND user_id=$2 AND status='site' FOR UPDATE`, [ids, req.uid])
    ).rows;
    if (rows.length !== ids.length) throw httpErr(409, "Некоторые номера уже недоступны");
    const stake = rows.reduce((a, p) => a + p.sell_price, 0);
    const goal = P.SELL_MID[target];
    if (stake >= goal) throw httpErr(400, "Ставка дороже цели — выберите редкость выше");
    if (rows.some((p) => p.tier >= target)) throw httpErr(400, "Номер-ставка не может быть той же или выше редкости, что цель");
    const chance = Math.min(UPGRADE_MAX_CHANCE, (stake / goal) * UPGRADE_EDGE);
    const roll = crypto.randomInt(0, 1000000) / 1000000;
    const win = roll < chance;
    await client.query(
      `UPDATE plates SET status='upgraded', note=$2, updated_at=now() WHERE id = ANY($1::bigint[])`,
      [ids, win ? "Апгрейд: успех" : "Апгрейд: сгорел"]
    );
    let plate = null;
    if (win) {
      const row = await insertPlateOfTier(client, req.uid, target, "upgrade");
      if (!row) throw httpErr(503, "Не удалось подобрать номер, попробуйте ещё раз");
      plate = plateOut(row);
    }
    return { win, chance, roll, plate };
  });
});

// Продать все номера на сайте (до выбранной редкости включительно)
app.post("/api/plates/sell-all", auth, (req, res) => {
  const maxTier = Math.min(6, Math.max(1, Math.floor(Number(req.body.maxTier) || 6)));
  withTx(res, async (client) => {
    const rows = (
      await client.query(
        `UPDATE plates SET status='sold', updated_at=now() WHERE user_id=$1 AND status='site' AND tier <= $2 RETURNING *`,
        [req.uid, maxTier]
      )
    ).rows;
    if (!rows.length) throw httpErr(409, "Нечего продавать");
    const sum = rows.reduce((a, p) => a + p.sell_price, 0);
    await client.query(`INSERT INTO charges (user_id, amount, reason) VALUES ($1,$2,$3)`, [req.uid, -sum, "sellall:" + rows.length]);
    const { available } = await availableFor(client, req.uid, false);
    return { count: rows.length, sum, balance: available };
  });
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
    let cars = [];
    if (ids.length) {
      cars = (
        await client.query(
          `UPDATE cars SET status='delivering', updated_at=now()
           WHERE user_id = ANY($1::bigint[])
             AND (status='pending' OR (status='delivering' AND updated_at < now() - ($2 || ' seconds')::interval))
           RETURNING *`,
          [ids, String(REDELIVER_SEC)]
        )
      ).rows.map((c) => ({
        id: Number(c.id),
        userId: Number(c.user_id),
        carId: c.car_id,
        name: c.car_name,
        value: (CARS[c.car_id] || {}).value || 0,
      }));
    }
    res.json({ charges, plates, cars });
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
  const carResults = Array.isArray(req.body.cars) ? req.body.cars.slice(0, 200) : [];
  const client = await pool.connect();
  try {
    for (const r of carResults) {
      await client.query("BEGIN");
      if (r.ok) {
        await client.query(
          `UPDATE cars SET status='delivered', note=$2, updated_at=now() WHERE id=$1 AND status='delivering'`,
          [r.id, r.dup ? "Уже была — выдана повторка" : null]
        );
      } else {
        // машину выдать нельзя (её нет в игре) — возвращаем цену кейса
        const c = (
          await client.query(
            `UPDATE cars SET status='failed', note=$2, updated_at=now() WHERE id=$1 AND status='delivering' RETURNING *`,
            [r.id, String(r.reason || "Не удалось выдать машину").slice(0, 200)]
          )
        ).rows[0];
        if (c && c.paid > 0) {
          await client.query(`INSERT INTO charges (user_id, amount, reason) VALUES ($1,$2,$3)`, [c.user_id, -c.paid, "refundcar:" + c.id]);
        }
      }
      await client.query("COMMIT");
    }
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

// та же генерация/редкость, что на сервере, — для анимаций в браузере
const fs = require("fs");
const platesClientJs = fs
  .readFileSync(path.join(__dirname, "plates.js"), "utf8")
  .replace('const crypto = require("crypto");', "const crypto = { randomInt: (a, b) => a + Math.floor(Math.random() * (b - a)) };")
  .replace("module.exports =", "window.Plates =");
app.get("/js/plates.js", (req, res) => res.type("application/javascript").send("(function(){" + platesClientJs + "})();"));
app.use(express.static(path.join(__dirname, "public"), { maxAge: "5m" }));

initDb()
  .then(() => app.listen(PORT, () => console.log("Сайт запущен на порту " + PORT)))
  .catch((e) => {
    console.error("DB init failed", e);
    process.exit(1);
  });
