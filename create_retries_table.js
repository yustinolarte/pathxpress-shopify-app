
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

async function createRetriesTable() {
    try {
        await db.execute(`
            CREATE TABLE IF NOT EXISTS webhook_retries (
                id INT AUTO_INCREMENT PRIMARY KEY,
                shop_domain VARCHAR(255),
                payload JSON,
                error_message TEXT,
                retry_count INT DEFAULT 0,
                status ENUM('PENDING', 'PROCESSED', 'FAILED') DEFAULT 'PENDING',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
            )
        `);
        console.log("✅ Tabla webhook_retries creada.");
    } catch (err) {
        console.error("❌ Error creando tabla webhook_retries:", err);
    } finally {
        await db.end();
    }
}

createRetriesTable();
