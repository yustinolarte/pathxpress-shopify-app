
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
        // Agregar columna sync_mode
        await db.execute(`
            ALTER TABLE shopify_shops
            ADD COLUMN sync_mode ENUM('auto', 'tag', 'manual') DEFAULT 'auto' AFTER sync_tag
        `);
        console.log("✅ Columna sync_mode agregada a shopify_shops.");

        // Migrar datos existentes según auto_sync y sync_tag
        await db.execute(`
            UPDATE shopify_shops
            SET sync_mode = 'auto'
            WHERE auto_sync = 1
        `);
        await db.execute(`
            UPDATE shopify_shops
            SET sync_mode = 'tag'
            WHERE auto_sync = 0 AND sync_tag IS NOT NULL AND sync_tag != ''
        `);
        await db.execute(`
            UPDATE shopify_shops
            SET sync_mode = 'manual'
            WHERE auto_sync = 0 AND (sync_tag IS NULL OR sync_tag = '')
        `);
        console.log("✅ Datos migrados a sync_mode correctamente.");
    } catch (err) {
        if (err.code === 'ER_DUP_FIELDNAME') {
            console.log("ℹ️ La columna sync_mode ya existe.");
        } else {
            console.error("❌ Error al alterar tabla:", err);
        }
    } finally {
        await db.end();
    }
}

updateTable();
