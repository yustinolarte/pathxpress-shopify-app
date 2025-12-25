// Script to create shopify_shipments table
import mysql from "mysql2/promise";
import dotenv from "dotenv";

dotenv.config();

async function createShipmentsTable() {
    const db = await mysql.createConnection({
        host: process.env.DB_HOST,
        port: process.env.DB_PORT ? Number(process.env.DB_PORT) : 3306,
        user: process.env.DB_USER,
        password: process.env.DB_PASS,
        database: process.env.DB_NAME,
    });

    try {
        await db.execute(`
            CREATE TABLE IF NOT EXISTS shopify_shipments (
                id INT AUTO_INCREMENT PRIMARY KEY,
                shop_domain VARCHAR(255) NOT NULL,
                shop_order_id BIGINT NOT NULL,
                shop_order_name VARCHAR(50),
                consignee_name VARCHAR(255),
                consignee_phone VARCHAR(50),
                address_line1 VARCHAR(500),
                city VARCHAR(100),
                country VARCHAR(100),
                total_weight_kg DECIMAL(10,3),
                cod_amount DECIMAL(10,2),
                currency VARCHAR(10),
                status VARCHAR(50) DEFAULT 'PENDING_PICKUP',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                UNIQUE KEY unique_order (shop_domain, shop_order_id),
                INDEX idx_shop_domain (shop_domain),
                INDEX idx_status (status)
            )
        `);
        console.log("✅ Table shopify_shipments created or already exists.");
    } catch (err) {
        console.error("❌ Error creating table:", err);
    }

    await db.end();
    console.log("🏁 Done.");
}

createShipmentsTable();
