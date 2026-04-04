/**
 * Migration: add waybill_number column to shopify_shipments
 * This allows /app/orders to reliably detect synced orders via the local DB
 * instead of depending on the portal's orders table (cross-DB join).
 *
 * Usage: node update_schema_waybill.js
 */

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

async function run() {
    try {
        await db.execute(`
            ALTER TABLE shopify_shipments
            ADD COLUMN waybill_number VARCHAR(50) DEFAULT NULL
        `);
        console.log('✅ Column waybill_number added to shopify_shipments.');
    } catch (err) {
        if (err.code === 'ER_DUP_FIELDNAME') {
            console.log('ℹ️ Column waybill_number already exists.');
        } else {
            console.error('❌ Error:', err);
        }
    } finally {
        await db.end();
    }
}

run();
