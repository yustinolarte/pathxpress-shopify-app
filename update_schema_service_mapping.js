
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
            ADD COLUMN service_mapping JSON NULL
        `);
        console.log("✅ Column service_mapping (JSON) added to shopify_shops.");
    } catch (err) {
        if (err.code === 'ER_DUP_FIELDNAME') {
            console.log("ℹ️ Column service_mapping already exists.");
        } else {
            console.error("❌ Error altering table:", err);
        }
    } finally {
        await db.end();
    }
}

updateTable();
