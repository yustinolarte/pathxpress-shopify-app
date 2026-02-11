// Script to add last_synced_status column for fulfillment events tracking
import mysql from "mysql2/promise";
import dotenv from "dotenv";

dotenv.config();

async function addFulfillmentEventsColumn() {
    const db = await mysql.createConnection({
        host: process.env.DB_HOST,
        port: process.env.DB_PORT ? Number(process.env.DB_PORT) : 3306,
        user: process.env.DB_USER,
        password: process.env.DB_PASS,
        database: process.env.DB_NAME,
    });

    try {
        // Check if column already exists
        const [columns] = await db.execute(
            `SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS 
             WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'shopify_shipments' AND COLUMN_NAME = 'last_synced_status'`,
            [process.env.DB_NAME]
        );

        if (columns.length === 0) {
            await db.execute(`
                ALTER TABLE shopify_shipments 
                ADD COLUMN last_synced_status VARCHAR(50) DEFAULT NULL
            `);
            console.log("✅ Column 'last_synced_status' added to shopify_shipments.");
        } else {
            console.log("ℹ️ Column 'last_synced_status' already exists.");
        }

        // Also backfill: if shopify_fulfillment_id exists and is a real ID (not ALREADY_FULFILLED),
        // set last_synced_status to 'picked_up' so the event sync picks up from there
        const [updated] = await db.execute(`
            UPDATE shopify_shipments 
            SET last_synced_status = 'picked_up' 
            WHERE shopify_fulfillment_id IS NOT NULL 
              AND shopify_fulfillment_id != 'ALREADY_FULFILLED'
              AND last_synced_status IS NULL
        `);
        console.log(`✅ Backfilled ${updated.affectedRows} existing fulfilled shipments with last_synced_status = 'picked_up'.`);

    } catch (err) {
        console.error("❌ Error:", err);
    }

    await db.end();
    console.log("🏁 Done.");
}

addFulfillmentEventsColumn();
