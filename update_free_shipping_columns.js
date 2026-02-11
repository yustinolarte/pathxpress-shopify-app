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
        // Try to add _dom column directly first (if it doesn't exist)
        await db.execute(`
            ALTER TABLE shopify_shops 
            ADD COLUMN free_shipping_threshold_dom DECIMAL(10,2) DEFAULT NULL
        `);
        console.log("✅ Added free_shipping_threshold_dom column directly");
    } catch (err) {
        if (err.code === 'ER_DUP_FIELDNAME') {
            console.log("ℹ️ Column free_shipping_threshold_dom already exists");
        } else {
            // If direct add failed, maybe we need to rename the old column?
            try {
                // Rename existing column to DOM
                await db.execute(`
                    ALTER TABLE shopify_shops 
                    CHANGE COLUMN free_shipping_threshold free_shipping_threshold_dom DECIMAL(10,2) DEFAULT NULL
                `);
                console.log("✅ Renamed free_shipping_threshold to free_shipping_threshold_dom");
            } catch (renameErr) {
                if (renameErr.code === 'ER_BAD_FIELD_ERROR') {
                    console.log("ℹ️ original column free_shipping_threshold doesn't exist either");
                } else {
                    console.log("Note on rename:", renameErr.message);
                }
            }
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
