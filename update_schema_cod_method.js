import mysql from "mysql2/promise";
import dotenv from "dotenv";

dotenv.config();

async function runMigration() {
    console.log("🚀 Starting database migration...");

    try {
        const db = await mysql.createConnection({
            host: process.env.DB_HOST,
            port: process.env.DB_PORT ? Number(process.env.DB_PORT) : 3306,
            user: process.env.DB_USER,
            password: process.env.DB_PASS,
            database: process.env.DB_NAME,
        });

        console.log("✅ Connected to database.");

        try {
            await db.execute(`ALTER TABLE shopify_shops ADD COLUMN IF NOT EXISTS default_cod_method VARCHAR(10) NOT NULL DEFAULT 'cash'`);
            console.log("✅ Migration successful: default_cod_method column is ready.");
        } catch (e) {
            console.warn("⚠️ Migration warning:", e.message);
        }

        await db.end();
        console.log("🏁 Migration finished.");
    } catch (err) {
        console.error("❌ Fatal error connecting to database:", err.message);
        process.exit(1);
    }
}

runMigration();
