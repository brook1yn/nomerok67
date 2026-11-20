// Генерация номеров и редкость — точная копия логики игры
// (LicensePlateServer.generatePlate + ReplicatedStorage.PlateRenderer.getRarity)
const crypto = require("crypto");

const RUS_LETTERS = ["А", "В", "Е", "К", "М", "Н", "О", "Р", "С", "Т", "У", "Х"];
const BY_LETTERS = ["A", "B", "E", "I", "K", "M", "H", "O", "P", "C", "T", "X"];
const KZ_LETTERS = "ABCDEFGHJKLMNPRSTUVWXYZ".split("");

const RUS_REGIONS = [];
for (let i = 1; i <= 99; i++) RUS_REGIONS.push(String(i).padStart(2, "0"));
RUS_REGIONS.push(
  ..."102 113 116 118 121 123 124 125 134 142 150 152 154 156 159 161 163 164 168 169 172 173 174 176 177 178 186 188 190 196 197 198 199 702 716 725 750 761 763 774 777 790 797 799".split(" ")
);
const BY_REGIONS = ["1", "2", "3", "4", "5", "6", "7", "8"];
const KZ_REGIONS = [];
for (let i = 1; i <= 20; i++) KZ_REGIONS.push(String(i).padStart(2, "0"));

const COUNTRIES = ["RUS", "BY", "KZ"];

const RARITIES = [
  null,
  { tier: 1, name: "ОБЫЧНЫЙ", color: "rgb(150,156,172)" },
  { tier: 2, name: "НЕОБЫЧНЫЙ", color: "rgb(86,214,120)" },
  { tier: 3, name: "РЕДКИЙ", color: "rgb(70,160,255)" },
  { tier: 4, name: "ЭПИЧЕСКИЙ", color: "rgb(176,110,255)" },
  { tier: 5, name: "ЛЕГЕНДАРНЫЙ", color: "rgb(255,196,56)" },
  { tier: 6, name: "МИФИЧЕСКИЙ", color: "rgb(255,84,112)" },
];

const SELL_RANGES = [null, [100, 400], [200, 500], [600, 1500], [2500, 6000], [8000, 20000], [150000, 350000]];

const rnd = (n) => crypto.randomInt(0, n);
const pick = (arr) => arr[rnd(arr.length)];
const digit = () => String(rnd(10));

function generatePlate(country) {
  if (country === "BY") {
    return digit() + digit() + digit() + digit() + pick(BY_LETTERS) + pick(BY_LETTERS) + " " + pick(BY_REGIONS);
  }
  if (country === "KZ") {
    return digit() + digit() + digit() + pick(KZ_LETTERS) + pick(KZ_LETTERS) + pick(KZ_LETTERS) + " " + pick(KZ_REGIONS);
  }
  return pick(RUS_LETTERS) + digit() + digit() + digit() + pick(RUS_LETTERS) + pick(RUS_LETTERS) + " " + pick(RUS_REGIONS);
}

function split(plate) {
  const main = plate.split(" ")[0];
  const letters = [];
  const digits = [];
  for (const ch of main) {
    if (/\d/.test(ch)) digits.push(Number(ch));
    else letters.push(ch);
  }
  return { letters, digits };
}

function counts(arr) {
  const m = new Map();
  for (const x of arr) m.set(x, (m.get(x) || 0) + 1);
  return [...m.values()].sort((a, b) => b - a);
}

function groupScore(arr) {
  if (arr.length === 0) return 0;
  const c = counts(arr);
  if (c[0] === arr.length && arr.length > 1) return 3;
  if (c[0] >= 2) return 1;
  return 0;
}

function consecutive(d) {
  let up = true;
  let down = true;
  for (let i = 1; i < d.length; i++) {
    if (d[i] !== d[i - 1] + 1) up = false;
    if (d[i] !== d[i - 1] - 1) down = false;
  }
  return up || down;
}

function byScore(letters, digits) {
  const c = counts(digits);
  let s = 0;
  if (c[0] === 4) s = 5;
  else if (c[0] === 3) s = 2;
  else if (c[0] === 2) s = 1;
  else if (consecutive(digits)) s = 1;
  if (letters[0] === letters[1]) s += 1;
  return s;
}

function kzScore(letters, digits) {
  const c = counts(digits);
  let s = 0;
  if (c[0] === 3) {
    s = 3;
    if (digits[0] === 7) s += 1;
  } else if (c[0] === 2) s = 1;
  else if (consecutive(digits)) s = 1;
  const lc = counts(letters);
  if (lc[0] === 3) s += 3;
  else if (lc[0] === 2) s += 1;
  return s;
}

function tierFromScore(score) {
  if (score <= 0) return 1;
  if (score === 1) return 2;
  if (score === 2) return 3;
  if (score === 3) return 4;
  if (score <= 5) return 5;
  return 6;
}

function getRarity(country, plate) {
  const { letters, digits } = split(plate);
  let score;
  if (country === "KZ") score = kzScore(letters, digits);
  else if (country === "BY") score = byScore(letters, digits);
  else {
    score = groupScore(letters) + groupScore(digits);
    if (digits.length === 3 && consecutive(digits)) score += 1;
  }
  return RARITIES[tierFromScore(score)];
}

function getSellPrice(tier) {
  const [a, b] = SELL_RANGES[tier] || SELL_RANGES[1];
  return (Math.floor(a / 10) + rnd(Math.floor(b / 10) - Math.floor(a / 10) + 1)) * 10;
}

// как normalizePlate в игре: без пробелов, в верхнем регистре
function normalizePlate(plate) {
  return plate.replace(/\s+/g, "").toUpperCase();
}

module.exports = { COUNTRIES, RARITIES, SELL_RANGES, generatePlate, getRarity, getSellPrice, normalizePlate };
