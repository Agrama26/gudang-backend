// server.js - Enhanced with Role-Based Access Control
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const qrcode = require("qrcode");
const mysql = require("mysql2/promise");
const XLSX = require("xlsx"); // NEW: Excel processing
const multer = require("multer"); // NEW: File upload
require("dotenv").config();
const emailService = require("./services/emailService");

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || "isiRahasiaPanjangBanget";

// ---------- Configure Multer for File Upload ----------
const storage = multer.memoryStorage();
const upload = multer({
  storage: storage,
  limits: {
    fileSize: 10 * 1024 * 1024, // 10MB limit
  },
  fileFilter: (req, file, cb) => {
    // Accept only Excel files
    const allowedMimes = [
      "application/vnd.ms-excel",
      "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ];
    if (allowedMimes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error("Only Excel files (.xls, .xlsx) are allowed"));
    }
  },
});

// ---------- Middlewares ----------
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));

// CORS Configuration
const ALLOWED_ORIGINS = [
  "http://localhost:5173",
  "http://localhost:3000",
  "http://localhost:4173",
  "https://gudang-permana-seven.vercel.app",
  "https://gudang-frontend-git-main-agrama26s-projects.vercel.app/",
  /\.vercel\.app$/,
  /localhost:\d+$/,
];

app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin) return callback(null, true);
      const isAllowed = ALLOWED_ORIGINS.some((allowedOrigin) => {
        if (allowedOrigin instanceof RegExp) {
          return allowedOrigin.test(origin);
        }
        return allowedOrigin === origin;
      });
      if (isAllowed) {
        callback(null, true);
      } else {
        console.log("❌ CORS blocked origin:", origin);
        callback(new Error(`CORS: Origin ${origin} not allowed`));
      }
    },
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "X-Requested-With"],
    preflightContinue: false,
    optionsSuccessStatus: 204,
  })
);

// Security headers
app.use((req, res, next) => {
  res.header("X-Content-Type-Options", "nosniff");
  res.header("X-Frame-Options", "DENY");
  res.header("X-XSS-Protection", "1; mode=block");
  next();
});

// Logging
app.use((req, res, next) => {
  const timestamp = new Date().toISOString();
  console.log(
    `[${timestamp}] ${req.method} ${req.originalUrl} - Origin: ${req.headers.origin || "none"}`
  );
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
      reconnect: true,
    });

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

// ---------- Auth Middlewares ----------
function authenticateToken(req, res, next) {
  const authHeader = req.headers.authorization || "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;

  if (!token) {
    return res.status(401).json({
      message: "Access token required",
      error: "MISSING_TOKEN",
    });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      console.log("❌ JWT verification failed:", err.message);
      return res.status(403).json({
        message: "Invalid or expired token",
        error: "INVALID_TOKEN",
      });
    }
    req.user = user;
    next();
  });
}

// Admin-only middleware
function requireAdmin(req, res, next) {
  if (req.user.role !== "admin") {
    return res.status(403).json({
      message: "Access denied. Admin privileges required.",
      error: "INSUFFICIENT_PERMISSIONS",
    });
  }
  next();
}

// ---------- Schema & Seed ----------
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
    // Users table with additional fields
    await conn.query(`
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(100) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        role ENUM('admin','staff') NOT NULL DEFAULT 'staff',
        full_name VARCHAR(255),
        email VARCHAR(255),
        is_active BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        last_login TIMESTAMP NULL
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
        created_by INT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    // Riwayat table with user tracking
    await conn.query(`
      CREATE TABLE IF NOT EXISTS riwayat_barang (
        id INT AUTO_INCREMENT PRIMARY KEY,
        barang_id INT NOT NULL,
        status ENUM('READY','TERPAKAI','RUSAK') NOT NULL,
        lokasi VARCHAR(255) NOT NULL,
        keterangan TEXT,
        kondisi VARCHAR(50) NOT NULL,
        changed_by INT,
        tanggal TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        CONSTRAINT fk_rb_barang FOREIGN KEY (barang_id) REFERENCES barang(id) ON DELETE CASCADE,
        FOREIGN KEY (changed_by) REFERENCES users(id) ON DELETE SET NULL
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    // Activity logs table for admin monitoring
    await conn.query(`
      CREATE TABLE IF NOT EXISTS activity_logs (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT,
        action VARCHAR(100) NOT NULL,
        target_type VARCHAR(50),
        target_id INT,
        details TEXT,
        ip_address VARCHAR(45),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
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
      "Medan",
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
      "Batam",
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
      "Jakarta",
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

// Activity logging helper
async function logActivity(
  userId,
  action,
  targetType = null,
  targetId = null,
  details = null,
  ipAddress = null
) {
  try {
    await pool.query(
      `INSERT INTO activity_logs (user_id, action, target_type, target_id, details, ip_address)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [userId, action, targetType, targetId, details, ipAddress]
    );
  } catch (error) {
    console.error("Error logging activity:", error);
  }
}

// ---------- Excel Helper Functions ----------

// Generate Excel template
function generateExcelTemplate() {
  const templateData = [
    {
      nama: "Router Mikrotik RB750",
      type: "Network Equipment",
      mac_address: "00:1B:44:11:3A:B7",
      serial_number: "MK001234",
      kondisi: "Baik",
      status: "READY",
      keterangan: "Router untuk kantor cabang",
      lokasi: "Server Room A-1",
      kota: "Medan",
    },
    {
      nama: "TP-Link Switch 24 Port",
      type: "Switch",
      mac_address: "A4:2B:B0:C1:D2:E3",
      serial_number: "TP567890",
      kondisi: "Baru",
      status: "READY",
      keterangan: "Switch baru dari vendor",
      lokasi: "Warehouse B-2",
      kota: "Batam",
    },
  ];

  const worksheet = XLSX.utils.json_to_sheet(templateData);
  const workbook = XLSX.utils.book_new();
  XLSX.utils.book_append_sheet(workbook, worksheet, "Template Barang");

  // Add instructions sheet
  const instructions = [
    {
      Field: "nama",
      Required: "YES",
      Description: "Nama barang (contoh: Router Mikrotik RB750)",
    },
    { Field: "type", Required: "YES", Description: "Tipe/Model barang" },
    {
      Field: "mac_address",
      Required: "NO",
      Description: "MAC Address (format: XX:XX:XX:XX:XX:XX)",
    },
    {
      Field: "serial_number",
      Required: "NO",
      Description: "Serial Number (harus unik)",
    },
    {
      Field: "kondisi",
      Required: "YES",
      Description: "Kondisi: Baru, Baik, Rusak Ringan, Rusak Berat",
    },
    {
      Field: "status",
      Required: "YES",
      Description: "Status: READY, TERPAKAI, RUSAK",
    },
    { Field: "keterangan", Required: "NO", Description: "Keterangan tambahan" },
    {
      Field: "lokasi",
      Required: "YES",
      Description: "Lokasi penempatan barang",
    },
    {
      Field: "kota",
      Required: "YES",
      Description: "Kota: Medan, Batam, Pekan Baru, Jakarta, Tarutung",
    },
  ];

  const instructionsSheet = XLSX.utils.json_to_sheet(instructions);
  XLSX.utils.book_append_sheet(workbook, instructionsSheet, "Instructions");

  return XLSX.write(workbook, { type: "buffer", bookType: "xlsx" });
}

// Validate import data
function validateBarangData(data) {
  const errors = [];
  const validKondisi = ["Baru", "Baik", "Rusak Ringan", "Rusak Berat"];
  const validStatus = ["READY", "TERPAKAI", "RUSAK"];
  const validKota = ["Medan", "Batam", "Pekan Baru", "Jakarta", "Tarutung"];

  data.forEach((item, index) => {
    const row = index + 2; // Excel row (accounting for header)

    // Required fields
    if (!item.nama || item.nama.trim() === "") {
      errors.push(`Row ${row}: Nama barang wajib diisi`);
    }
    if (!item.type || item.type.trim() === "") {
      errors.push(`Row ${row}: Type barang wajib diisi`);
    }
    if (!item.kondisi || item.kondisi.trim() === "") {
      errors.push(`Row ${row}: Kondisi wajib diisi`);
    }
    if (!item.status || item.status.trim() === "") {
      errors.push(`Row ${row}: Status wajib diisi`);
    }
    if (!item.lokasi || item.lokasi.trim() === "") {
      errors.push(`Row ${row}: Lokasi wajib diisi`);
    }
    if (!item.kota || item.kota.trim() === "") {
      errors.push(`Row ${row}: Kota wajib diisi`);
    }

    // Validate values
    if (item.kondisi && !validKondisi.includes(item.kondisi)) {
      errors.push(
        `Row ${row}: Kondisi harus salah satu dari: ${validKondisi.join(", ")}`
      );
    }
    if (item.status && !validStatus.includes(item.status)) {
      errors.push(
        `Row ${row}: Status harus salah satu dari: ${validStatus.join(", ")}`
      );
    }
    if (item.kota && !validKota.includes(item.kota)) {
      errors.push(
        `Row ${row}: Kota harus salah satu dari: ${validKota.join(", ")}`
      );
    }

    // Validate MAC address format if provided
    if (item.mac_address && item.mac_address.trim() !== "") {
      const macRegex = /^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/;
      if (!macRegex.test(item.mac_address)) {
        errors.push(
          `Row ${row}: Format MAC address tidak valid (gunakan format XX:XX:XX:XX:XX:XX)`
        );
      }
    }
  });

  return errors;
}

// ---------- Routes ----------

// Health check
app.get("/", (req, res) => {
  res.json({
    message: "Warehouse API",
    status: "OK",
    timestamp: new Date().toISOString(),
    endpoints: [
      "/api/health",
      "/api/auth/login",
      "/api/barang",
      "/api/admin/users",
    ],
  });
});

app.get("/api/health", (req, res) => {
  res.json({
    status: "OK",
    message: "Warehouse API is running",
    timestamp: new Date().toISOString(),
    database: pool ? "Connected" : "Disconnected",
  });
});

// ---------- Auth Routes ----------
app.post("/api/auth/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res
        .status(400)
        .json({ message: "Username and password required" });
    }

    console.log(`🔐 Login attempt for user: ${username}`);

    const [rows] = await pool.query(
      "SELECT * FROM users WHERE username = ? AND is_active = TRUE",
      [username]
    );
    const user = rows[0];

    if (!user) {
      console.log(`❌ User not found or inactive: ${username}`);
      await logActivity(
        null,
        "LOGIN_FAILED",
        "user",
        null,
        `Failed login attempt for ${username}`,
        req.ip
      );
      return res.status(401).json({ message: "Invalid credentials" });
    }

    if (!user.password || user.password.length < 55) {
      console.log(`❌ Invalid password hash for user: ${username}`);
      return res
        .status(500)
        .json({ message: "User password hash invalid in DB" });
    }

    const isValidPassword = bcrypt.compareSync(password, user.password);
    if (!isValidPassword) {
      console.log(`❌ Invalid password for user: ${username}`);
      await logActivity(
        user.id,
        "LOGIN_FAILED",
        "user",
        user.id,
        `Failed password attempt`,
        req.ip
      );
      return res.status(401).json({ message: "Invalid credentials" });
    }

    // Update last login
    await pool.query("UPDATE users SET last_login = NOW() WHERE id = ?", [
      user.id,
    ]);

    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: "24h" }
    );

    console.log(`✅ Login successful for user: ${username} (${user.role})`);
    await logActivity(
      user.id,
      "LOGIN_SUCCESS",
      "user",
      user.id,
      `Successful login`,
      req.ip
    );

    res.json({
      token,
      user: {
        id: user.id,
        username: user.username,
        role: user.role,
        full_name: user.full_name,
        email: user.email,
      },
    });
  } catch (error) {
    console.error("❌ Login error:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

// ---------- NEW: Import/Export Routes ----------

// Download Excel Template
app.get("/api/barang/template", authenticateToken, async (req, res) => {
  try {
    console.log(`📥 Template download requested by user: ${req.user.username}`);

    const buffer = generateExcelTemplate();

    await logActivity(
      req.user.id,
      "TEMPLATE_DOWNLOADED",
      "barang",
      null,
      "Downloaded import template",
      req.ip
    );

    res.setHeader(
      "Content-Type",
      "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    );
    res.setHeader(
      "Content-Disposition",
      "attachment; filename=Template_Import_Barang.xlsx"
    );
    res.send(buffer);
  } catch (error) {
    console.error("❌ Template generation error:", error);
    res.status(500).json({ message: "Failed to generate template" });
  }
});

// Import Excel
app.post(
  "/api/barang/import",
  authenticateToken,
  upload.single("file"),
  async (req, res) => {
    try {
      if (!req.file) {
        return res.status(400).json({ message: "No file uploaded" });
      }

      console.log(`📤 Import initiated by user: ${req.user.username}`);

      // Parse Excel file
      const workbook = XLSX.read(req.file.buffer, { type: "buffer" });
      const sheetName = workbook.SheetNames[0];
      const worksheet = workbook.Sheets[sheetName];
      const jsonData = XLSX.utils.sheet_to_json(worksheet);

      if (jsonData.length === 0) {
        return res.status(400).json({ message: "Excel file is empty" });
      }

      // Validate data
      const validationErrors = validateBarangData(jsonData);
      if (validationErrors.length > 0) {
        return res.status(400).json({
          message: "Validation failed",
          errors: validationErrors,
        });
      }

      // Check for duplicate serial numbers in the file
      const serialNumbers = jsonData.map((item) => item.serial_number);
      const duplicates = serialNumbers.filter(
        (item, index) => serialNumbers.indexOf(item) !== index
      );
      if (duplicates.length > 0) {
        return res.status(400).json({
          message: "Duplicate serial numbers found in file",
          duplicates: [...new Set(duplicates)],
        });
      }

      // Check for existing serial numbers in database
      const [existingItems] = await pool.query(
        "SELECT serial_number FROM barang WHERE serial_number IN (?)",
        [serialNumbers]
      );

      if (existingItems.length > 0) {
        return res.status(400).json({
          message: "Some serial numbers already exist in database",
          existing: existingItems.map((item) => item.serial_number),
        });
      }

      // Import data
      const conn = await pool.getConnection();
      let successCount = 0;
      let failedItems = [];

      try {
        await conn.beginTransaction();

        for (const item of jsonData) {
          try {
            const [result] = await conn.query(
              `INSERT INTO barang 
            (nama, type, mac_address, serial_number, kondisi, status, keterangan, lokasi, kota, created_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
              [
                item.nama,
                item.type,
                item.mac_address || null,
                item.serial_number,
                item.kondisi,
                item.status,
                item.keterangan || "",
                item.lokasi,
                item.kota,
                req.user.id,
              ]
            );

            // Create initial history entry
            await conn.query(
              "INSERT INTO riwayat_barang (barang_id, status, lokasi, keterangan, kondisi, changed_by) VALUES (?, ?, ?, ?, ?, ?)",
              [
                result.insertId,
                item.status,
                item.lokasi,
                "Imported from Excel",
                item.kondisi,
                req.user.id,
              ]
            );

            successCount++;
          } catch (itemError) {
            failedItems.push({
              serial_number: item.serial_number,
              error: itemError.message,
            });
          }
        }

        await conn.commit();

        await logActivity(
          req.user.id,
          "IMPORT_SUCCESS",
          "barang",
          null,
          `Imported ${successCount} items from Excel`,
          req.ip
        );

        res.json({
          message: "Import completed",
          success: successCount,
          failed: failedItems.length,
          failedItems: failedItems,
        });
      } catch (error) {
        await conn.rollback();
        throw error;
      } finally {
        conn.release();
      }
    } catch (error) {
      console.error("❌ Import error:", error);
      res.status(500).json({ message: "Import failed", error: error.message });
    }
  }
);

// Export to Excel
app.get("/api/barang/export", authenticateToken, async (req, res) => {
  try {
    console.log(`📥 Export requested by user: ${req.user.username}`);

    const [items] = await pool.query(`
      SELECT 
        nama,
        type,
        mac_address,
        serial_number,
        kondisi,
        status,
        keterangan,
        lokasi,
        kota,
        created_at,
        updated_at
      FROM barang
      ORDER BY created_at DESC
    `);

    if (items.length === 0) {
      return res.status(404).json({ message: "No data to export" });
    }

    // Format dates for Excel
    const formattedItems = items.map((item) => ({
      ...item,
      created_at: item.created_at
        ? new Date(item.created_at).toLocaleString("id-ID")
        : "",
      updated_at: item.updated_at
        ? new Date(item.updated_at).toLocaleString("id-ID")
        : "",
    }));

    const worksheet = XLSX.utils.json_to_sheet(formattedItems);
    const workbook = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(workbook, worksheet, "Data Barang");

    const buffer = XLSX.write(workbook, { type: "buffer", bookType: "xlsx" });

    await logActivity(
      req.user.id,
      "EXPORT_SUCCESS",
      "barang",
      null,
      `Exported ${items.length} items to Excel`,
      req.ip
    );

    const filename = `Data_Barang_${new Date().toISOString().split("T")[0]}.xlsx`;

    res.setHeader(
      "Content-Type",
      "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    );
    res.setHeader("Content-Disposition", `attachment; filename=${filename}`);
    res.send(buffer);
  } catch (error) {
    console.error("❌ Export error:", error);
    res.status(500).json({ message: "Export failed", error: error.message });
  }
});

// ---------- Admin User Management Routes ----------

// Get all users (Admin only)
app.get(
  "/api/admin/users",
  authenticateToken,
  requireAdmin,
  async (req, res) => {
    try {
      const [users] = await pool.query(`
      SELECT id, username, role, full_name, email, is_active, created_at, updated_at, last_login
      FROM users
      ORDER BY created_at DESC
    `);

      res.json(users);
    } catch (error) {
      console.error("❌ Get users error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  }
);

// Create new user (Admin only)
app.post(
  "/api/admin/users",
  authenticateToken,
  requireAdmin,
  async (req, res) => {
    try {
      const { username, password, role, full_name, email } = req.body;

      if (!username || !password || !role) {
        return res
          .status(400)
          .json({ message: "Username, password, and role are required" });
      }

      if (!["admin", "staff"].includes(role)) {
        return res
          .status(400)
          .json({ message: "Invalid role. Must be 'admin' or 'staff'" });
      }

      const hash = bcrypt.hashSync(password, 10);

      const [result] = await pool.query(
        `INSERT INTO users (username, password, role, full_name, email, is_active)
       VALUES (?, ?, ?, ?, ?, TRUE)`,
        [username, hash, role, full_name || null, email || null]
      );

      await logActivity(
        req.user.id,
        "USER_CREATED",
        "user",
        result.insertId,
        `Created user: ${username} with role ${role}`,
        req.ip
      );

      res.status(201).json({
        message: "User created successfully",
        id: result.insertId,
        username,
        role,
      });
    } catch (error) {
      console.error("❌ Create user error:", error);
      if (error.code === "ER_DUP_ENTRY") {
        return res.status(400).json({ message: "Username already exists" });
      }
      res.status(500).json({ message: "Internal server error" });
    }
  }
);

// Update user (Admin only)
app.put(
  "/api/admin/users/:id",
  authenticateToken,
  requireAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;
      const { username, password, role, full_name, email, is_active } =
        req.body;

      // Don't allow admin to deactivate themselves
      if (parseInt(id) === req.user.id && is_active === false) {
        return res
          .status(400)
          .json({ message: "Cannot deactivate your own account" });
      }

      const updates = [];
      const values = [];

      if (username !== undefined) {
        updates.push("username = ?");
        values.push(username);
      }
      if (password) {
        updates.push("password = ?");
        values.push(bcrypt.hashSync(password, 10));
      }
      if (role !== undefined) {
        if (!["admin", "staff"].includes(role)) {
          return res.status(400).json({ message: "Invalid role" });
        }
        updates.push("role = ?");
        values.push(role);
      }
      if (full_name !== undefined) {
        updates.push("full_name = ?");
        values.push(full_name);
      }
      if (email !== undefined) {
        updates.push("email = ?");
        values.push(email);
      }
      if (is_active !== undefined) {
        updates.push("is_active = ?");
        values.push(is_active);
      }

      if (updates.length === 0) {
        return res.status(400).json({ message: "No fields to update" });
      }

      values.push(id);

      await pool.query(
        `UPDATE users SET ${updates.join(", ")} WHERE id = ?`,
        values
      );

      await logActivity(
        req.user.id,
        "USER_UPDATED",
        "user",
        id,
        `Updated user ID: ${id}`,
        req.ip
      );

      res.json({ message: "User updated successfully" });
    } catch (error) {
      console.error("❌ Update user error:", error);
      if (error.code === "ER_DUP_ENTRY") {
        return res.status(400).json({ message: "Username already exists" });
      }
      res.status(500).json({ message: "Internal server error" });
    }
  }
);

// Delete user (Admin only)
app.delete(
  "/api/admin/users/:id",
  authenticateToken,
  requireAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;

      // Don't allow admin to delete themselves
      if (parseInt(id) === req.user.id) {
        return res
          .status(400)
          .json({ message: "Cannot delete your own account" });
      }

      const [[user]] = await pool.query(
        "SELECT username FROM users WHERE id = ?",
        [id]
      );
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }

      await pool.query("DELETE FROM users WHERE id = ?", [id]);

      await logActivity(
        req.user.id,
        "USER_DELETED",
        "user",
        id,
        `Deleted user: ${user.username}`,
        req.ip
      );

      res.json({ message: "User deleted successfully" });
    } catch (error) {
      console.error("❌ Delete user error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  }
);

// Get activity logs (Admin only)
app.get(
  "/api/admin/activity-logs",
  authenticateToken,
  requireAdmin,
  async (req, res) => {
    try {
      const { limit = 100, offset = 0 } = req.query;

      const [logs] = await pool.query(
        `
      SELECT 
        al.*,
        u.username,
        u.role
      FROM activity_logs al
      LEFT JOIN users u ON al.user_id = u.id
      ORDER BY al.created_at DESC
      LIMIT ? OFFSET ?
    `,
        [parseInt(limit), parseInt(offset)]
      );

      const [[{ total }]] = await pool.query(
        "SELECT COUNT(*) as total FROM activity_logs"
      );

      res.json({
        logs,
        total,
        limit: parseInt(limit),
        offset: parseInt(offset),
      });
    } catch (error) {
      console.error("❌ Get activity logs error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  }
);

// Get dashboard statistics (Admin only)
app.get(
  "/api/admin/statistics",
  authenticateToken,
  requireAdmin,
  async (req, res) => {
    try {
      // User statistics
      const [[userStats]] = await pool.query(`
      SELECT 
        COUNT(*) as total_users,
        SUM(CASE WHEN role = 'admin' THEN 1 ELSE 0 END) as admin_count,
        SUM(CASE WHEN role = 'staff' THEN 1 ELSE 0 END) as staff_count,
        SUM(CASE WHEN is_active = TRUE THEN 1 ELSE 0 END) as active_users
      FROM users
    `);

      // Barang statistics
      const [[barangStats]] = await pool.query(`
      SELECT 
        COUNT(*) as total_barang,
        SUM(CASE WHEN status = 'READY' THEN 1 ELSE 0 END) as ready_count,
        SUM(CASE WHEN status = 'TERPAKAI' THEN 1 ELSE 0 END) as terpakai_count,
        SUM(CASE WHEN status = 'RUSAK' THEN 1 ELSE 0 END) as rusak_count
      FROM barang
    `);

      // Recent activity count
      const [[activityStats]] = await pool.query(`
      SELECT 
        COUNT(*) as today_activities
      FROM activity_logs
      WHERE DATE(created_at) = CURDATE()
    `);

      res.json({
        users: userStats,
        barang: barangStats,
        activity: activityStats,
      });
    } catch (error) {
      console.error("❌ Get statistics error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  }
);

// ---------- Barang Routes ----------
app.get("/api/barang", authenticateToken, async (req, res) => {
  try {
    const { kotaFilter } = req.query;

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
  } catch (error) {
    console.error("❌ Get barang error:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.get("/api/barang/:id", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;

    const [[barang]] = await pool.query("SELECT * FROM barang WHERE id = ?", [
      id,
    ]);
    if (!barang) {
      return res.status(404).json({ message: "Barang not found" });
    }

    const [riwayat] = await pool.query(
      `SELECT rb.*, u.username as changed_by_name 
       FROM riwayat_barang rb
       LEFT JOIN users u ON rb.changed_by = u.id
       WHERE rb.barang_id = ? 
       ORDER BY rb.tanggal DESC`,
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
      (nama, type, mac_address, serial_number, kondisi, status, keterangan, lokasi, kota, created_by)
      VALUES (?,?,?,?,?,?,?,?,?,?)`,
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
        req.user.id,
      ]
    );

    const barangId = result.insertId;
    await pool.query(
      "INSERT INTO riwayat_barang (barang_id, status, lokasi, keterangan, kondisi, changed_by) VALUES (?,?,?,?,?,?)",
      [
        barangId,
        status,
        lokasi,
        "Barang baru ditambahkan",
        kondisi,
        req.user.id,
      ]
    );

    await logActivity(
      req.user.id,
      "BARANG_CREATED",
      "barang",
      barangId,
      `Created barang: ${nama}`,
      req.ip
    );

    res
      .status(201)
      .json({ message: "Barang berhasil ditambahkan", id: barangId });
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

    const [[current]] = await pool.query("SELECT * FROM barang WHERE id = ?", [
      id,
    ]);
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
      "INSERT INTO riwayat_barang (barang_id, status, lokasi, keterangan, kondisi, changed_by) VALUES (?,?,?,?,?,?)",
      [
        id,
        status,
        newLokasi,
        newKeterangan || `Status diubah menjadi ${status}`,
        newKondisi,
        req.user.id,
      ]
    );

    await logActivity(
      req.user.id,
      "BARANG_UPDATED",
      "barang",
      id,
      `Updated barang status to ${status}`,
      req.ip
    );

    res.json({ message: "Status dan lokasi berhasil diupdate" });
  } catch (error) {
    console.error("❌ Update status error:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.delete(
  "/api/barang/:id",
  authenticateToken,
  requireAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;

      const [[row]] = await pool.query("SELECT nama FROM barang WHERE id = ?", [
        id,
      ]);
      if (!row) {
        return res.status(404).json({ message: "Barang not found" });
      }

      await pool.query("DELETE FROM barang WHERE id = ?", [id]);

      await logActivity(
        req.user.id,
        "BARANG_DELETED",
        "barang",
        id,
        `Deleted barang: ${row.nama}`,
        req.ip
      );

      res.json({ message: "Barang berhasil dihapus" });
    } catch (error) {
      console.error("❌ Delete barang error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  }
);

// QR Code route
app.get("/api/qr/:id", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;

    const [[barang]] = await pool.query("SELECT * FROM barang WHERE id = ?", [
      id,
    ]);
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

// UPDATE endpoint POST /api/admin/users untuk mengirim email
app.post(
  "/api/admin/users",
  authenticateToken,
  requireAdmin,
  async (req, res) => {
    try {
      const { username, password, role, full_name, email } = req.body;

      if (!username || !password || !role) {
        return res
          .status(400)
          .json({ message: "Username, password, and role are required" });
      }

      if (!["admin", "staff"].includes(role)) {
        return res
          .status(400)
          .json({ message: "Invalid role. Must be 'admin' or 'staff'" });
      }

      const hash = bcrypt.hashSync(password, 10);

      const [result] = await pool.query(
        `INSERT INTO users (username, password, role, full_name, email, is_active)
       VALUES (?, ?, ?, ?, ?, TRUE)`,
        [username, hash, role, full_name || null, email || null]
      );

      await logActivity(
        req.user.id,
        "USER_CREATED",
        "user",
        result.insertId,
        `Created user: ${username} with role ${role}`,
        req.ip
      );

      // Send welcome email to new user
      let emailSent = false;
      if (email && process.env.ENABLE_EMAIL_NOTIFICATIONS === "true") {
        console.log(`📧 Attempting to send welcome email to: ${email}`);

        const userData = {
          username,
          role,
          full_name,
          email,
        };

        try {
          const emailResult = await emailService.sendUserCreatedEmail(
            userData,
            password
          );

          if (emailResult.success) {
            console.log(`✅ Welcome email sent successfully to ${email}`);
            emailSent = true;

            // Send notification to admin
            emailService
              .sendAdminNotification(userData, req.user.username)
              .then((result) => {
                if (result.success) {
                  console.log(`✅ Admin notification sent`);
                }
              })
              .catch((err) =>
                console.error("Admin notification error:", err.message)
              );
          } else {
            console.log(
              `⚠️ Failed to send welcome email: ${emailResult.message}`
            );
          }
        } catch (error) {
          console.error(`❌ Email sending error:`, error.message);
        }
      } else {
        console.log(
          `⚠️ Email not sent - Email: ${email || "NOT PROVIDED"}, Notifications enabled: ${process.env.ENABLE_EMAIL_NOTIFICATIONS}`
        );
      }

      res.status(201).json({
        message: "User created successfully",
        id: result.insertId,
        username,
        role,
        emailSent: emailSent,
        emailAddress: email || null,
      });
    } catch (error) {
      console.error("❌ Create user error:", error);
      if (error.code === "ER_DUP_ENTRY") {
        return res.status(400).json({ message: "Username already exists" });
      }
      res.status(500).json({ message: "Internal server error" });
    }
  }
);

// UPDATE endpoint PUT /api/admin/users/:id untuk notifikasi status change
app.put(
  "/api/admin/users/:id",
  authenticateToken,
  requireAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;
      const { username, password, role, full_name, email, is_active } =
        req.body;

      // Don't allow admin to deactivate themselves
      if (parseInt(id) === req.user.id && is_active === false) {
        return res
          .status(400)
          .json({ message: "Cannot deactivate your own account" });
      }

      // Get current user data
      const [[currentUser]] = await pool.query(
        "SELECT * FROM users WHERE id = ?",
        [id]
      );
      if (!currentUser) {
        return res.status(404).json({ message: "User not found" });
      }

      const updates = [];
      const values = [];
      let statusChanged = false;

      if (username !== undefined) {
        updates.push("username = ?");
        values.push(username);
      }
      if (password) {
        updates.push("password = ?");
        values.push(bcrypt.hashSync(password, 10));
      }
      if (role !== undefined) {
        if (!["admin", "staff"].includes(role)) {
          return res.status(400).json({ message: "Invalid role" });
        }
        updates.push("role = ?");
        values.push(role);
      }
      if (full_name !== undefined) {
        updates.push("full_name = ?");
        values.push(full_name);
      }
      if (email !== undefined) {
        updates.push("email = ?");
        values.push(email);
      }
      if (is_active !== undefined) {
        updates.push("is_active = ?");
        values.push(is_active);
        statusChanged = is_active !== currentUser.is_active;
      }

      if (updates.length === 0) {
        return res.status(400).json({ message: "No fields to update" });
      }

      values.push(id);

      await pool.query(
        `UPDATE users SET ${updates.join(", ")} WHERE id = ?`,
        values
      );

      await logActivity(
        req.user.id,
        "USER_UPDATED",
        "user",
        id,
        `Updated user ID: ${id}`,
        req.ip
      );

      // Send email if status changed
      if (
        statusChanged &&
        currentUser.email &&
        process.env.ENABLE_EMAIL_NOTIFICATIONS === "true"
      ) {
        emailService
          .sendStatusChangedEmail(
            {
              username: currentUser.username,
              email: currentUser.email,
            },
            is_active
          )
          .then((result) => {
            if (result.success) {
              console.log(
                `✅ Status change email sent to ${currentUser.email}`
              );
            }
          })
          .catch((error) =>
            console.error("Error sending status change email:", error)
          );
      }

      res.json({ message: "User updated successfully" });
    } catch (error) {
      console.error("❌ Update user error:", error);
      if (error.code === "ER_DUP_ENTRY") {
        return res.status(400).json({ message: "Username already exists" });
      }
      res.status(500).json({ message: "Internal server error" });
    }
  }
);

// ADD new endpoint untuk test email
app.get(
  "/api/admin/test-email",
  authenticateToken,
  requireAdmin,
  async (req, res) => {
    try {
      const result = await emailService.testConnection();
      res.json(result);
    } catch (error) {
      console.error("❌ Email test error:", error);
      res.status(500).json({ success: false, error: error.message });
    }
  }
);

// Error handlers
app.use((req, res) => {
  res.status(404).json({
    message: "Route not found",
    path: req.originalUrl,
    method: req.method,
  });
});

app.use((err, req, res, next) => {
  console.error("❌ Unhandled error:", err);
  res.status(500).json({
    message: "Internal server error",
    ...(process.env.NODE_ENV === "development" && { error: err.message }),
  });
});

async function runMigrations() {
  if (process.env.NODE_ENV === "production") {
    console.log("🔄 Running production migrations...");
    try {
      // Import migrate script
      require("./migrate");
      console.log("✅ Migrations completed");
    } catch (error) {
      console.error("❌ Migration failed:", error);
      // Don't exit, continue with existing schema
    }
  }
}

// Update startServer function
async function startServer() {
  try {
    await initDatabase();

    // Run migrations in production
    if (process.env.NODE_ENV === "production") {
      await runMigrations();
    }

    app.listen(PORT, "0.0.0.0", () => {
      console.log(`🚀 Warehouse API running on http://0.0.0.0:${PORT}`);
    });
  } catch (error) {
    console.error("❌ Failed to start server:", error);
    process.exit(1);
  }
}

// ---------- Start Server ----------
// async function startServer() {
//   try {
//     await initDatabase();

//     app.listen(PORT, "0.0.0.0", () => {
//       console.log(`🚀 Warehouse API running on http://0.0.0.0:${PORT}`);
//       console.log(
//         `🗄️ Database: MySQL (${process.env.MYSQL_DB || "warehouse"})`
//       );
//       console.log(`🌍 Environment: ${process.env.NODE_ENV || "development"}`);
//       console.log(`🔗 CORS origins configured for Vercel deployment`);
//     });
//   } catch (error) {
//     console.error("❌ Failed to start server:", error);
//     process.exit(1);
//   }
// }

startServer();
