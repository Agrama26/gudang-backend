app.use(cors({
  origin: ["http://localhost:5173", "https://gudang-permana-seven.vercel.app"],
  credentials: true
}));


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
const JWT_SECRET = process.env.JWT_SECRET || "isiRahasiaPanjangBanget";

// ---------- Middlewares ----------
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// CORS Configuration - Fixed untuk Vercel
const ALLOWED_ORIGINS = [
  "http://localhost:5173",
  "http://localhost:3000",
  "http://localhost:4173",
  "https://gudang-permana-seven.vercel.app",
  "https://gudang-frontend-git-main-agrama26s-projects.vercel.app/", // jika URL Vercel berbeda
  /\.vercel\.app$/,  // Regex untuk semua subdomain vercel
  /localhost:\d+$/   // Regex untuk localhost dengan port apapun
];

app.use(cors({
  origin: (origin, callback) => {
    // Allow requests with no origin (mobile apps, etc.)
    if (!origin) return callback(null, true);
    
    // Check if origin is in allowed list
    const isAllowed = ALLOWED_ORIGINS.some(allowedOrigin => {
      if (allowedOrigin instanceof RegExp) {
        return allowedOrigin.test(origin);
      }
      return allowedOrigin === origin;
    });
    
    if (isAllowed) {
      callback(null, true);
    } else {
      console.log('❌ CORS blocked origin:', origin);
      callback(new Error(`CORS: Origin ${origin} not allowed`));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  preflightContinue: false,
  optionsSuccessStatus: 204
}));

// Add security headers
app.use((req, res, next) => {
  res.header('X-Content-Type-Options', 'nosniff');
  res.header('X-Frame-Options', 'DENY');
  res.header('X-XSS-Protection', '1; mode=block');
  next();
});

// Enhanced logging
app.use((req, res, next) => {
  const timestamp = new Date().toISOString();
  console.log(`[${timestamp}] ${req.method} ${req.originalUrl} - Origin: ${req.headers.origin || 'none'}`);
  next();
});

// ---------- MySQL Pool ----------
let pool;

async function initDatabase() {
  const HOST = process.env.MYSQLHOST || process.env.MYSQL_HOST || "localhost";
  const PORT = Number(process.env.MYSQLPORT || process.env.MYSQL_PORT || 3306);
  const USER = process.env.MYSQLUSER || process.env.MYSQL_USER || "root";
  const PASS = process.env.MYSQLPASSWORD || process.env.MYSQL_PASSWORD || "";
  const DB = process.env.MYSQLDATABASE || process.env.MYSQL_DB || "warehouse";

  console.log(`🔗 Connecting to MySQL: ${USER}@${HOST}:${PORT}/${DB}`);

  try {
    pool = mysql.createPool({
      host: HOST,
      port: PORT,
      user: USER,
      password: PASS,
      database: DB,
      waitForConnections: true,
      connectionLimit: 10,
      queueLimit: 0,
      acquireTimeout: 60000,
      timeout: 60000,
      reconnect: true
    });

    // Test connection
    const connection = await pool.getConnection();
    await connection.ping();
    connection.release();
    
    console.log("✅ MySQL connected successfully");
    
    await initSchema();
    console.log("✅ Database schema initialized");
    
    return true;
  } catch (error) {
    console.error("❌ MySQL connection failed:", error);
    throw error;
  }
}

// ---------- Auth middleware ----------
function authenticateToken(req, res, next) {
  const authHeader = req.headers.authorization || "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;
  
  if (!token) {
    return res.status(401).json({ 
      message: "Access token required",
      error: "MISSING_TOKEN" 
    });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      console.log("❌ JWT verification failed:", err.message);
      return res.status(403).json({ 
        message: "Invalid or expired token",
        error: "INVALID_TOKEN" 
      });
    }
    req.user = user;
    next();
  });
}

// ---------- Schema & seed ----------
async function upsertUser(username, passwordPlain, role) {
  const hash = bcrypt.hashSync(passwordPlain, 10);
  await pool.query(
    `INSERT INTO users (username, password, role)
     VALUES (?, ?, ?)
     ON DUPLICATE KEY UPDATE role = VALUES(role)`,
    [username, hash, role]
  );
  
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
    // Users table
    await conn.query(`
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(100) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        role ENUM('admin','staff') NOT NULL DEFAULT 'staff',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    // Barang table
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
        kota VARCHAR(100),
        qr_code LONGTEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    // Riwayat table
    await conn.query(`
      CREATE TABLE IF NOT EXISTS riwayat_barang (
        id INT AUTO_INCREMENT PRIMARY KEY,
        barang_id INT NOT NULL,
        status ENUM('READY','TERPAKAI','RUSAK') NOT NULL,
        lokasi VARCHAR(255) NOT NULL,
        keterangan TEXT,
        kondisi VARCHAR(50) NOT NULL,
        tanggal TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        CONSTRAINT fk_rb_barang FOREIGN KEY (barang_id) REFERENCES barang(id) ON DELETE CASCADE
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);
  } finally {
    conn.release();
  }

  // Create default users
  await upsertUser("admin", "admin123", "admin");
  await upsertUser("staff", "staff123", "staff");

  // Seed sample data
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
      "Medan"
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
      "Batam"
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
      "Jakarta"
    ],
  ];
  
  for (const s of samples) {
    try {
      await pool.query(
        `INSERT IGNORE INTO barang
         (nama,type,mac_address,serial_number,kondisi,status,keterangan,lokasi,kota)
         VALUES (?,?,?,?,?,?,?,?,?)`,
        s
      );
    } catch (error) {
      console.log("Sample data already exists or error:", error.message);
    }
  }
}

// ---------- Routes ----------

// Health check
app.get("/", (req, res) => {
  res.json({ 
    message: "Warehouse API", 
    status: "OK",
    timestamp: new Date().toISOString(),
    endpoints: ["/api/health", "/api/auth/login", "/api/barang"]
  });
});

app.get("/api/health", (req, res) => {
  res.json({ 
    status: "OK", 
    message: "Warehouse API is running",
    timestamp: new Date().toISOString(),
    database: pool ? "Connected" : "Disconnected"
  });
});

// Auth routes
app.post("/api/auth/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ message: "Username and password required" });
    }

    console.log(`🔐 Login attempt for user: ${username}`);

    const [rows] = await pool.query("SELECT * FROM users WHERE username = ?", [username]);
    const user = rows[0];
    
    if (!user) {
      console.log(`❌ User not found: ${username}`);
      return res.status(401).json({ message: "Invalid credentials" });
    }

    if (!user.password || user.password.length < 55) {
      console.log(`❌ Invalid password hash for user: ${username}`);
      return res.status(500).json({ message: "User password hash invalid in DB" });
    }

    const isValidPassword = bcrypt.compareSync(password, user.password);
    if (!isValidPassword) {
      console.log(`❌ Invalid password for user: ${username}`);
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: "24h" }
    );

    console.log(`✅ Login successful for user: ${username}`);

    res.json({
      token,
      user: { id: user.id, username: user.username, role: user.role },
    });
  } catch (error) {
    console.error("❌ Login error:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

// Barang routes
app.get("/api/barang", authenticateToken, async (req, res) => {
  try {
    const { kotaFilter } = req.query;
    
    let query = "SELECT id, nama, type, mac_address, serial_number, kondisi, status, keterangan, lokasi, kota, qr_code FROM barang";
    const params = [];

    if (kotaFilter) {
      query += " WHERE kota = ?";
      params.push(kotaFilter);
    }

    query += " ORDER BY created_at DESC";

    const [rows] = await pool.query(query, params);
    res.json(rows);
  } catch (error) {
    console.error("❌ Get barang error:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.get("/api/barang/:id", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    
    const [[barang]] = await pool.query("SELECT * FROM barang WHERE id = ?", [id]);
    if (!barang) {
      return res.status(404).json({ message: "Barang not found" });
    }

    const [riwayat] = await pool.query(
      "SELECT * FROM riwayat_barang WHERE barang_id = ? ORDER BY tanggal DESC",
      [id]
    );
    
    res.json({ barang, riwayat });
  } catch (error) {
    console.error("❌ Get barang detail error:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.post("/api/barang", authenticateToken, async (req, res) => {
  try {
    const {
      nama,
      type,
      mac_address,
      serial_number,
      kondisi,
      status,
      lokasi,
      kota,
      keterangan = "",
    } = req.body;

    const [result] = await pool.query(
      `INSERT INTO barang
      (nama, type, mac_address, serial_number, kondisi, status, keterangan, lokasi, kota)
      VALUES (?,?,?,?,?,?,?,?,?)`,
      [nama, type, mac_address, serial_number, kondisi, status, keterangan, lokasi, kota]
    );

    const barangId = result.insertId;
    await pool.query(
      "INSERT INTO riwayat_barang (barang_id, status, lokasi, keterangan, kondisi) VALUES (?,?,?,?,?)",
      [barangId, status, lokasi, "Barang baru ditambahkan", kondisi]
    );

    res.status(201).json({ message: "Barang berhasil ditambahkan", id: barangId });
  } catch (error) {
    console.error("❌ Create barang error:", error);
    if (error.code === "ER_DUP_ENTRY") {
      return res.status(400).json({ message: "Serial number already exists" });
    }
    res.status(500).json({ message: "Internal server error" });
  }
});

app.put("/api/barang/:id/status", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { status, lokasi, keterangan, kondisi } = req.body;

    const [[current]] = await pool.query("SELECT * FROM barang WHERE id = ?", [id]);
    if (!current) {
      return res.status(404).json({ message: "Barang not found" });
    }

    const newLokasi = lokasi || current.lokasi;
    const newKondisi = kondisi || current.kondisi;
    const newKeterangan = keterangan || current.keterangan;

    await pool.query(
      "UPDATE barang SET status=?, lokasi=?, kondisi=?, keterangan=? WHERE id=?",
      [status, newLokasi, newKondisi, newKeterangan, id]
    );
    
    await pool.query(
      "INSERT INTO riwayat_barang (barang_id, status, lokasi, keterangan, kondisi) VALUES (?,?,?,?,?)",
      [id, status, newLokasi, newKeterangan || `Status diubah menjadi ${status}`, newKondisi]
    );

    res.json({ message: "Status dan lokasi berhasil diupdate" });
  } catch (error) {
    console.error("❌ Update status error:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.delete("/api/barang/:id", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    
    const [[row]] = await pool.query("SELECT id FROM barang WHERE id = ?", [id]);
    if (!row) {
      return res.status(404).json({ message: "Barang not found" });
    }

    await pool.query("DELETE FROM barang WHERE id = ?", [id]);
    res.json({ message: "Barang berhasil dihapus" });
  } catch (error) {
    console.error("❌ Delete barang error:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

// QR Code route
app.get("/api/qr/:id", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    
    const [[barang]] = await pool.query("SELECT * FROM barang WHERE id = ?", [id]);
    if (!barang) {
      return res.status(404).json({ message: "Barang not found" });
    }

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
  } catch (error) {
    console.error("❌ QR generation error:", error);
    res.status(500).json({ message: "Failed to generate QR" });
  }
});

// Error handlers
app.use((req, res) => {
  res.status(404).json({ 
    message: "Route not found",
    path: req.originalUrl,
    method: req.method 
  });
});

app.use((err, req, res, next) => {
  console.error("❌ Unhandled error:", err);
  res.status(500).json({ 
    message: "Internal server error",
    ...(process.env.NODE_ENV === 'development' && { error: err.message })
  });
});

// ---------- Start Server ----------
async function startServer() {
  try {
    await initDatabase();
    
    app.listen(PORT, "0.0.0.0", () => {
      console.log(`🚀 Warehouse API running on http://0.0.0.0:${PORT}`);
      console.log(`🗄️ Database: MySQL (${process.env.MYSQL_DB || "warehouse"})`);
      console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
      console.log(`🔗 CORS origins configured for Vercel deployment`);
    });
  } catch (error) {
    console.error("❌ Failed to start server:", error);
    process.exit(1);
  }
}

startServer();