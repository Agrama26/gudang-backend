// server.js
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const qrcode = require("qrcode");
const mysql = require("mysql2/promise");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || "your-secret-key-change-this";

// ---------- Middlewares ----------
app.use(express.json());
app.use(
  cors({
    origin: [
      "http://localhost:5173",
      "http://localhost:3000",
      "http://192.168.1.22:3000",
    ],
    credentials: false,
  })
);
// log request biar gampang debug
app.use((req, _res, next) => {
  console.log(`[REQ] ${req.method} ${req.originalUrl}`);
  next();
});

// ---------- MySQL Pool ----------
let pool;
(async () => {
  pool = mysql.createPool({
    host: process.env.MYSQL_HOST || "localhost",
    port: process.env.MYSQL_PORT ? Number(process.env.MYSQL_PORT) : 3306,
    user: process.env.MYSQL_USER || "root",
    password: process.env.MYSQL_PASSWORD || "",
    database: process.env.MYSQL_DB || "warehouse",
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
  });

  await initSchema();
  console.log("✅ MySQL connected & schema ready");
})().catch((e) => {
  console.error("❌ MySQL connection failed:", e);
  process.exit(1);
});

// ---------- Auth middleware (HOISTED) ----------
function authenticateToken(req, res, next) {
  const authHeader = req.headers.authorization || "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;
  if (!token) return res.status(401).json({ message: "Access token required" });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: "Invalid token" });
    req.user = user;
    next();
  });
}

// ---------- Schema & seed ----------
async function upsertUser(username, passwordPlain, role) {
  const hash = bcrypt.hashSync(passwordPlain, 10);
  // insert kalau belum ada
  await pool.query(
    `INSERT INTO users (username, password, role)
     VALUES (?, ?, ?)
     ON DUPLICATE KEY UPDATE role = VALUES(role)`,
    [username, hash, role]
  );
  // reset password default bila diminta
  if (process.env.RESEED_DEFAULTS === "true") {
    await pool.query(`UPDATE users SET password=? WHERE username=?`, [
      hash,
      username,
    ]);
  }
}

async function initSchema() {
  const conn = await pool.getConnection();
  try {
    await conn.query(`
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(100) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        role ENUM('admin','staff') NOT NULL DEFAULT 'staff',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    await conn.query(`
      CREATE TABLE IF NOT EXISTS barang (
        id INT AUTO_INCREMENT PRIMARY KEY,
        nama VARCHAR(255) NOT NULL,
        type VARCHAR(100) NOT NULL,
        mac_address VARCHAR(32),
        serial_number VARCHAR(100) UNIQUE NOT NULL,
        kondisi VARCHAR(50) NOT NULL,
        status ENUM('READY','TERPAKAI','RUSAK') NOT NULL DEFAULT 'READY',
        keterangan TEXT,
        lokasi VARCHAR(255) NOT NULL,
        kota VARCHAR(100),  /* Menambahkan kolom kota */
        qr_code LONGTEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    await conn.query(`
      CREATE TABLE IF NOT EXISTS riwayat_barang (
        id INT AUTO_INCREMENT PRIMARY KEY,
        barang_id INT NOT NULL,
        status ENUM('READY','TERPAKAI','RUSAK') NOT NULL,
        lokasi VARCHAR(255) NOT NULL,
        keterangan TEXT,
        kondisi VARCHAR(50) NOT NULL,  -- <== TAMBAHKAN INI
        tanggal TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        CONSTRAINT fk_rb_barang FOREIGN KEY (barang_id) REFERENCES barang(id) ON DELETE CASCADE
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);
  } finally {
    conn.release();
  }

  // pastikan akun default ada
  await upsertUser("admin", "admin123", "admin");
  await upsertUser("staff", "staff123", "staff");

  // seed barang (idempotent dengan INSERT IGNORE)
  const samples = [
    [
      "Router Cisco 2960",
      "Network Equipment",
      "00:1B:44:11:3A:B7",
      "FCW1947C0GH",
      "Baik",
      "READY",
      "Ready untuk deployment",
      "Warehouse A-1",
    ],
    [
      "Switch HP ProCurve",
      "Network Equipment",
      "00:1B:44:11:3A:B8",
      "FCW1947C0GI",
      "Baik",
      "TERPAKAI",
      "Sedang digunakan di lantai 2",
      "Gedung B Lt.2",
    ],
    [
      "Server Dell R740",
      "Server",
      "00:1B:44:11:3A:B9",
      "FCW1947C0GJ",
      "Rusak",
      "RUSAK",
      "Perlu maintenance power supply",
      "Maintenance Room",
    ],
  ];
  for (const s of samples) {
    await pool.query(
      `INSERT IGNORE INTO barang
       (nama,type,mac_address,serial_number,kondisi,status,keterangan,lokasi)
       VALUES (?,?,?,?,?,?,?,?)`,
      s
    );
  }
}

// ---------- Routes ----------
app.get("/", (_req, res) =>
  res.json({ message: "Warehouse API", docs: "/api/health" })
);

app.get("/api/health", (_req, res) =>
  res.json({ status: "OK", message: "Warehouse API is running" })
);

// Auth
app.post("/api/auth/login", async (req, res) => {
  const username = (req.body.username || "").trim();
  const password = (req.body.password || "").trim();

  const [rows] = await pool.query("SELECT * FROM users WHERE username = ?", [
    username,
  ]);
  const user = rows[0];
  if (!user) return res.status(401).json({ message: "Invalid credentials" });

  if (!user.password || user.password.length < 55) {
    return res
      .status(500)
      .json({ message: "User password hash invalid in DB" });
  }

  const ok = bcrypt.compareSync(password, user.password);
  if (!ok) return res.status(401).json({ message: "Invalid credentials" });

  const token = jwt.sign(
    { id: user.id, username: user.username, role: user.role },
    JWT_SECRET,
    { expiresIn: "24h" }
  );
  res.json({
    token,
    user: { id: user.id, username: user.username, role: user.role },
  });
});

// Barang list
app.get("/api/barang", authenticateToken, async (req, res) => {
  const { kotaFilter } = req.query; // Ambil filter kota dari query parameter

  let query =
    "SELECT id, nama, type, mac_address, serial_number, kondisi, status, keterangan, lokasi, kota, qr_code FROM barang";
  const params = [];

  if (kotaFilter) {
    query += " WHERE kota = ?";
    params.push(kotaFilter);
  }

  query += " ORDER BY created_at DESC";

  const [rows] = await pool.query(query, params);
  res.json(rows);
});

// Barang detail + riwayat
app.get("/api/barang/:id", authenticateToken, async (req, res) => {
  const { id } = req.params;
  const [[barang]] = await pool.query("SELECT * FROM barang WHERE id = ?", [
    id,
  ]);
  if (!barang) return res.status(404).json({ message: "Barang not found" });

  const [riwayat] = await pool.query(
    "SELECT * FROM riwayat_barang WHERE barang_id = ? ORDER BY tanggal DESC",
    [id]
  );
  res.json({ barang, riwayat });
});

// Barang create
app.post("/api/barang", authenticateToken, async (req, res) => {
  const {
    nama,
    type,
    mac_address,
    serial_number,
    kondisi, // Pastikan kondisi diterima di sini
    status,
    lokasi,
    kota,
    keterangan = "",
  } = req.body;

  try {
    const [result] = await pool.query(
      `INSERT INTO barang
      (nama, type, mac_address, serial_number, kondisi, status, keterangan, lokasi, kota)
      VALUES (?,?,?,?,?,?,?,?,?)`,
      [
        nama,
        type,
        mac_address,
        serial_number,
        kondisi,
        status,
        keterangan,
        lokasi,
        kota,
      ] // Pastikan kondisi disertakan
    );

    const barangId = result.insertId;
    await pool.query(
      "INSERT INTO riwayat_barang (barang_id, status, lokasi, keterangan, kondisi) VALUES (?,?,?, ?, ?)",
      [barangId, status, lokasi, "Barang baru ditambahkan", kondisi, keterangan] // Pastikan kondisi juga disertakan di riwayat
    );

    res
      .status(201)
      .json({ message: "Barang berhasil ditambahkan", id: barangId });
  } catch (err) {
    if (err && err.code === "ER_DUP_ENTRY") {
      return res.status(400).json({ message: "Serial number already exists" });
    }
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

// Update status + lokasi
app.put("/api/barang/:id/status", authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { status, lokasi, keterangan, kondisi } = req.body; // Pastikan kondisi ada di body

  const [[current]] = await pool.query("SELECT * FROM barang WHERE id = ?", [
    id,
  ]);
  if (!current) return res.status(404).json({ message: "Barang not found" });

  const newLokasi = lokasi || current.lokasi;
  const newKondisi = kondisi || current.kondisi;
  const newKeterangan = keterangan || current.keterangan;

  await pool.query(
    "UPDATE barang SET status=?, lokasi=?, kondisi=?, keterangan=? WHERE id=?",
    [
      status,
      newLokasi,
      newKondisi, // Update kondisi
      newKeterangan,
      id,
    ]
  );
  await pool.query(
    "INSERT INTO riwayat_barang (barang_id, status, lokasi, keterangan, kondisi) VALUES (?,?,?,?,?)",
    [
      id,
      status,
      newLokasi,
      newKeterangan || `Status diubah menjadi ${status}`,
      newKondisi,
    ] // Simpan kondisi di riwayat
  );

  res.json({ message: "Status dan lokasi berhasil diupdate" });
});

// Delete barang
app.delete("/api/barang/:id", authenticateToken, async (req, res) => {
  const { id } = req.params;
  const [[row]] = await pool.query("SELECT id FROM barang WHERE id = ?", [id]);
  if (!row) return res.status(404).json({ message: "Barang not found" });

  await pool.query("DELETE FROM barang WHERE id = ?", [id]); // riwayat terhapus via CASCADE
  res.json({ message: "Barang berhasil dihapus" });
});

// QR
app.get("/api/qr/:id", authenticateToken, async (req, res) => {
  const { id } = req.params;
  const [[barang]] = await pool.query("SELECT * FROM barang WHERE id = ?", [
    id,
  ]);
  if (!barang) return res.status(404).json({ message: "Barang not found" });

  try {
    const payload = JSON.stringify({
      id: barang.id,
      sn: barang.serial_number,
      nama: barang.nama,
    });
    const dataUrl = await qrcode.toDataURL(payload, {
      errorCorrectionLevel: "M",
    });
    await pool.query("UPDATE barang SET qr_code=? WHERE id=?", [dataUrl, id]);
    res.json({ id: barang.id, qr: dataUrl });
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: "Failed to generate QR" });
  }
});

// ---------- 404 & Error ----------
app.use((_req, res) => res.status(404).json({ message: "Route not found" }));
app.use((err, _req, res, _next) => {
  console.error("Unhandled error:", err);
  res.status(500).json({ message: "Internal server error" });
});

// ---------- Start ----------
app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 Warehouse API running on http://localhost:${PORT}`);
  console.log(`🗄️  DB: MySQL (${process.env.MYSQL_DB || "warehouse"})`);
});
