
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
                pathxpress_client_id INT NULL,
                default_service_type VARCHAR(20) DEFAULT 'DOM',
                auto_sync TINYINT DEFAULT 1,
                sync_tag VARCHAR(100) NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
            )
        `);
        console.log("✅ Table shopify_shops created or already exists.");
    } catch (err) {
        console.error("❌ Error creating table shopify_shops:", err);
    } finally {
        await db.end();
    }
}

createShopsTable();
