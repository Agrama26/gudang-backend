// backend/migrations/migrate-add-user-tracking.js
require("dotenv").config();
const mysql = require("mysql2/promise");

async function migrate() {
  console.log("🔄 Starting database migration...\n");

  const config = {
    host: process.env.MYSQL_HOST || "localhost",
    port: parseInt(process.env.MYSQL_PORT || "3306"),
    user: process.env.MYSQL_USER || "root",
    password: process.env.MYSQL_PASSWORD || "",
    database: process.env.MYSQL_DB || "warehouse",
  };

  let connection;

  try {
    connection = await mysql.createConnection(config);
    console.log("✅ Connected to MySQL\n");

    // Check if columns already exist
    console.log("1️⃣ Checking existing columns...");
    const [barangCols] = await connection.query(
      "SHOW COLUMNS FROM barang LIKE 'created_by'"
    );
    const [riwayatCols] = await connection.query(
      "SHOW COLUMNS FROM riwayat_barang LIKE 'changed_by'"
    );

    // Add created_by to barang table
    if (barangCols.length === 0) {
      console.log("   Adding created_by column to barang table...");
      await connection.query(`
        ALTER TABLE barang 
        ADD COLUMN created_by INT NULL AFTER qr_code
      `);
      console.log("   ✅ Column created_by added to barang");

      // Add foreign key
      await connection.query(`
        ALTER TABLE barang 
        ADD CONSTRAINT fk_barang_created_by 
        FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
      `);
      console.log("   ✅ Foreign key constraint added");
    } else {
      console.log("   ⏭️  Column created_by already exists in barang");
    }

    // Add changed_by to riwayat_barang table
    if (riwayatCols.length === 0) {
      console.log("\n2️⃣ Adding changed_by column to riwayat_barang table...");
      await connection.query(`
        ALTER TABLE riwayat_barang 
        ADD COLUMN changed_by INT NULL AFTER kondisi
      `);
      console.log("   ✅ Column changed_by added to riwayat_barang");

      // Add foreign key
      await connection.query(`
        ALTER TABLE riwayat_barang 
        ADD CONSTRAINT fk_rb_changed_by 
        FOREIGN KEY (changed_by) REFERENCES users(id) ON DELETE SET NULL
      `);
      console.log("   ✅ Foreign key constraint added");
    } else {
      console.log("   ⏭️  Column changed_by already exists in riwayat_barang");
    }

    // Verify changes
    console.log("\n3️⃣ Verifying schema...");
    const [barangSchema] = await connection.query("DESCRIBE barang");
    const [riwayatSchema] = await connection.query("DESCRIBE riwayat_barang");

    const hasCreatedBy = barangSchema.some((col) => col.Field === "created_by");
    const hasChangedBy = riwayatSchema.some(
      (col) => col.Field === "changed_by"
    );

    if (hasCreatedBy && hasChangedBy) {
      console.log("   ✅ All columns verified successfully");
    } else {
      console.log("   ⚠️  Warning: Some columns may be missing");
    }

    console.log("\n✅ Migration completed successfully!\n");

    // Show updated schema
    console.log("📋 Updated barang table schema:");
    console.table(
      barangSchema.map((col) => ({
        Field: col.Field,
        Type: col.Type,
        Null: col.Null,
        Key: col.Key,
      }))
    );

    console.log("\n📋 Updated riwayat_barang table schema:");
    console.table(
      riwayatSchema.map((col) => ({
        Field: col.Field,
        Type: col.Type,
        Null: col.Null,
        Key: col.Key,
      }))
    );
  } catch (error) {
    console.error("\n❌ Migration failed:", error.message);
    console.error("Error details:", error);
    process.exit(1);
  } finally {
    if (connection) {
      await connection.end();
      console.log("\n🔌 Database connection closed");
    }
  }
}

// Run migration
migrate()
  .then(() => {
    console.log("\n🎉 Migration completed! You can now restart your server.");
    process.exit(0);
  })
  .catch((error) => {
    console.error("\n❌ Migration error:", error);
    process.exit(1);
  });
