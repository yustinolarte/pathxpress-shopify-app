
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
        // Añadir columna shopify_fulfillment_id si no existe
        // Nota: MySQL no tiene "ADD COLUMN IF NOT EXISTS" nativo en todas las versiones, 
        // pero podemos intentar ejecutarlo y capturar el error si ya existe.
        await db.execute(`
            ALTER TABLE shopify_shipments
            ADD COLUMN shopify_fulfillment_id VARCHAR(255) NULL
        `);
        console.log("✅ Column shopify_fulfillment_id added.");
    } catch (err) {
        if (err.code === 'ER_DUP_FIELDNAME') {
            console.log("ℹ️ Column shopify_fulfillment_id already exists.");
        } else {
            console.error("❌ Error altering table:", err);
        }
    } finally {
        await db.end();
    }
}

updateTable();
