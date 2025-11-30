
import mysql from "mysql2/promise";
import dotenv from "dotenv";
dotenv.config();

const db = mysql.createPool({
    host: process.env.DB_HOST,
    port: process.env.DB_PORT ? Number(process.env.DB_PORT) : 3306,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME,
});

async function updateTable() {
    try {
        await db.execute(`
            ALTER TABLE shopify_shops
            ADD COLUMN auto_sync BOOLEAN DEFAULT TRUE,
            ADD COLUMN sync_tag VARCHAR(255) DEFAULT NULL
        `);
        console.log("✅ Columns auto_sync and sync_tag added to shopify_shops.");
    } catch (err) {
        if (err.code === 'ER_DUP_FIELDNAME') {
            console.log("ℹ️ Columns already exist.");
        } else {
            console.error("❌ Error altering table:", err);
        }
    } finally {
        await db.end();
    }
}

updateTable();
