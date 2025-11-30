
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

async function createShopsTable() {
    try {
        await db.execute(`
            CREATE TABLE IF NOT EXISTS shopify_shops (
                shop_domain VARCHAR(255) PRIMARY KEY,
                access_token VARCHAR(255),
                shop_name VARCHAR(255),
                email VARCHAR(255),
                phone VARCHAR(50),
                address1 VARCHAR(255),
                address2 VARCHAR(255),
                city VARCHAR(100),
                province VARCHAR(100),
                country VARCHAR(100),
                zip VARCHAR(20),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
            )
        `);
        console.log("✅ Tabla shopify_shops creada o ya existente.");
    } catch (err) {
        console.error("❌ Error creando tabla shopify_shops:", err);
    } finally {
        await db.end();
    }
}

createShopsTable();
