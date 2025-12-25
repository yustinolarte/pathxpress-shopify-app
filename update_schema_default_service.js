// Script to add 'default_service_type' column to shopify_shops table
import mysql from "mysql2/promise";
import dotenv from "dotenv";

dotenv.config();

async function updateSchema() {
    const db = await mysql.createConnection({
        host: process.env.DB_HOST,
        port: process.env.DB_PORT ? Number(process.env.DB_PORT) : 3306,
        user: process.env.DB_USER,
        password: process.env.DB_PASS,
        database: process.env.DB_NAME,
    });

    try {
        // Add default_service_type column
        await db.execute(`
            ALTER TABLE shopify_shops
            ADD COLUMN default_service_type VARCHAR(20) DEFAULT 'DOM'
        `);
        console.log("✅ Column 'default_service_type' added to shopify_shops.");
    } catch (err) {
        if (err.code === 'ER_DUP_FIELDNAME') {
            console.log("ℹ️ Column 'default_service_type' already exists.");
        } else {
            console.error("⛔ Error:", err);
        }
    }

    await db.end();
    console.log("🏁 Schema update complete.");
}

updateSchema();
