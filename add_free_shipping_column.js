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

async function addFreeShippingColumn() {
    try {
        await db.execute(`
            ALTER TABLE shopify_shops 
            ADD COLUMN free_shipping_threshold DECIMAL(10,2) DEFAULT NULL
        `);
        console.log("✅ Column free_shipping_threshold added to shopify_shops.");
    } catch (err) {
        if (err.code === 'ER_DUP_FIELDNAME') {
            console.log("ℹ️ Column free_shipping_threshold already exists.");
        } else {
            console.error("❌ Error adding column:", err.message);
        }
    } finally {
        await db.end();
    }
}

addFreeShippingColumn();
