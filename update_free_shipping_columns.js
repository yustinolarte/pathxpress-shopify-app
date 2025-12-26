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

async function updateFreeShippingColumns() {
    try {
        // Rename existing column to DOM
        await db.execute(`
            ALTER TABLE shopify_shops 
            CHANGE COLUMN free_shipping_threshold free_shipping_threshold_dom DECIMAL(10,2) DEFAULT NULL
        `);
        console.log("✅ Renamed free_shipping_threshold to free_shipping_threshold_dom");
    } catch (err) {
        if (err.code === 'ER_BAD_FIELD_ERROR') {
            console.log("ℹ️ Column free_shipping_threshold doesn't exist or already renamed");
        } else {
            console.log("Note:", err.message);
        }
    }

    try {
        // Add express column
        await db.execute(`
            ALTER TABLE shopify_shops 
            ADD COLUMN free_shipping_threshold_express DECIMAL(10,2) DEFAULT NULL
        `);
        console.log("✅ Added column free_shipping_threshold_express");
    } catch (err) {
        if (err.code === 'ER_DUP_FIELDNAME') {
            console.log("ℹ️ Column free_shipping_threshold_express already exists");
        } else {
            console.log("Note:", err.message);
        }
    }

    await db.end();
    console.log("Done!");
}

updateFreeShippingColumns();
