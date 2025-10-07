// backend/migrate.js - Production Database Migration
const mysql = require('mysql2/promise');
require('dotenv').config();

console.log('🚀 Starting Database Migration for Railway...\n');

async function runMigration() {
  const config = {
    host: process.env.MYSQLHOST || process.env.MYSQL_HOST || 'localhost',
    port: parseInt(process.env.MYSQLPORT || process.env.MYSQL_PORT || '3306'),
    user: process.env.MYSQLUSER || process.env.MYSQL_USER || 'root',
    password: process.env.MYSQLPASSWORD || process.env.MYSQL_PASSWORD || '',
    database: process.env.MYSQLDATABASE || process.env.MYSQL_DB || 'warehouse'
  };

  console.log('📊 Database Configuration:');
  console.log(`   Host: ${config.host}`);
  console.log(`   Port: ${config.port}`);
  console.log(`   User: ${config.user}`);
  console.log(`   Database: ${config.database}\n`);

  let connection;

  try {
    // Connect to database
    connection = await mysql.createConnection(config);
    console.log('✅ Connected to MySQL database\n');

    // Run migrations in order
    console.log('🔄 Running migrations...\n');

    // Migration 1: Create users table with new fields
    console.log('1️⃣ Checking users table...');
    const [usersTables] = await connection.query(
      "SHOW TABLES LIKE 'users'"
    );

    if (usersTables.length === 0) {
      console.log('   Creating users table...');
      await connection.query(`
        CREATE TABLE users (
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
      console.log('   ✅ Users table created');
    } else {
      console.log('   ⏭️  Users table exists, checking columns...');
      
      // Check and add missing columns
      const columnsToAdd = [
        { name: 'full_name', sql: 'ALTER TABLE users ADD COLUMN full_name VARCHAR(255) AFTER role' },
        { name: 'email', sql: 'ALTER TABLE users ADD COLUMN email VARCHAR(255) AFTER full_name' },
        { name: 'is_active', sql: 'ALTER TABLE users ADD COLUMN is_active BOOLEAN DEFAULT TRUE AFTER email' },
        { name: 'updated_at', sql: 'ALTER TABLE users ADD COLUMN updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP AFTER created_at' },
        { name: 'last_login', sql: 'ALTER TABLE users ADD COLUMN last_login TIMESTAMP NULL AFTER updated_at' }
      ];

      for (const col of columnsToAdd) {
        const [colExists] = await connection.query(
          `SHOW COLUMNS FROM users LIKE '${col.name}'`
        );
        if (colExists.length === 0) {
          console.log(`   Adding column ${col.name}...`);
          await connection.query(col.sql);
          console.log(`   ✅ Column ${col.name} added`);
        }
      }
    }

    // Migration 2: Create barang table
    console.log('\n2️⃣ Checking barang table...');
    const [barangTables] = await connection.query(
      "SHOW TABLES LIKE 'barang'"
    );

    if (barangTables.length === 0) {
      console.log('   Creating barang table...');
      await connection.query(`
        CREATE TABLE barang (
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
      console.log('   ✅ Barang table created');
    } else {
      console.log('   ⏭️  Barang table exists, checking columns...');
      
      // Check and add created_by column
      const [createdByCol] = await connection.query(
        "SHOW COLUMNS FROM barang LIKE 'created_by'"
      );
      
      if (createdByCol.length === 0) {
        console.log('   Adding created_by column...');
        await connection.query(`
          ALTER TABLE barang 
          ADD COLUMN created_by INT AFTER qr_code,
          ADD FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
        `);
        console.log('   ✅ Column created_by added');
      }
    }

    // Migration 3: Create riwayat_barang table
    console.log('\n3️⃣ Checking riwayat_barang table...');
    const [riwayatTables] = await connection.query(
      "SHOW TABLES LIKE 'riwayat_barang'"
    );

    if (riwayatTables.length === 0) {
      console.log('   Creating riwayat_barang table...');
      await connection.query(`
        CREATE TABLE riwayat_barang (
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
      console.log('   ✅ Riwayat_barang table created');
    } else {
      console.log('   ⏭️  Riwayat_barang table exists, checking columns...');
      
      // Check and add changed_by column
      const [changedByCol] = await connection.query(
        "SHOW COLUMNS FROM riwayat_barang LIKE 'changed_by'"
      );
      
      if (changedByCol.length === 0) {
        console.log('   Adding changed_by column...');
        await connection.query(`
          ALTER TABLE riwayat_barang 
          ADD COLUMN changed_by INT AFTER kondisi,
          ADD FOREIGN KEY (changed_by) REFERENCES users(id) ON DELETE SET NULL
        `);
        console.log('   ✅ Column changed_by added');
      }
    }

    // Migration 4: Create activity_logs table
    console.log('\n4️⃣ Checking activity_logs table...');
    const [activityTables] = await connection.query(
      "SHOW TABLES LIKE 'activity_logs'"
    );

    if (activityTables.length === 0) {
      console.log('   Creating activity_logs table...');
      await connection.query(`
        CREATE TABLE activity_logs (
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
      console.log('   ✅ Activity_logs table created');
    } else {
      console.log('   ⏭️  Activity_logs table already exists');
    }

    // Verify all tables
    console.log('\n5️⃣ Verifying schema...');
    const [allTables] = await connection.query('SHOW TABLES');
    console.log('   Tables in database:');
    allTables.forEach(table => {
      const tableName = Object.values(table)[0];
      console.log(`   ✓ ${tableName}`);
    });

    console.log('\n✅ All migrations completed successfully!\n');

    // Show table structures
    console.log('📋 Final Schema:\n');
    
    const tables = ['users', 'barang', 'riwayat_barang', 'activity_logs'];
    for (const table of tables) {
      const [tableExists] = await connection.query(`SHOW TABLES LIKE '${table}'`);
      if (tableExists.length > 0) {
        console.log(`\n📊 ${table}:`);
        const [columns] = await connection.query(`DESCRIBE ${table}`);
        console.table(columns.map(col => ({
          Field: col.Field,
          Type: col.Type,
          Null: col.Null,
          Key: col.Key
        })));
      }
    }

  } catch (error) {
    console.error('\n❌ Migration failed:', error.message);
    console.error('Error details:', error);
    process.exit(1);
  } finally {
    if (connection) {
      await connection.end();
      console.log('\n🔌 Database connection closed');
    }
  }
}

// Run migration
runMigration()
  .then(() => {
    console.log('\n🎉 Migration completed successfully!');
    console.log('✅ Database is ready for production use.\n');
    process.exit(0);
  })
  .catch(error => {
    console.error('\n❌ Migration error:', error);
    process.exit(1);
  });