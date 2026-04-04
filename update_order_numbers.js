/**
 * One-time migration: backfill orders.orderNumber for orders synced before the orderNumber fix.
 *
 * The fulfillment sync functions (syncShipmentsToShopify, syncFulfillmentEvents) do:
 *   JOIN orders o ON (o.orderNumber = s.shop_order_name AND o.clientId = ss.pathxpress_client_id)
 *
 * Old orders have orderNumber = NULL → JOIN fails → fulfillment never syncs.
 * This script matches each NULL-orderNumber order to its shopify_shipment by creation time (±2 min).
 *
 * Usage: node update_order_numbers.js
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
        // Preview: how many orders are affected
        const [preview] = await db.execute(`SELECT COUNT(*) AS cnt FROM orders WHERE orderNumber IS NULL`);
        console.log(`Orders with NULL orderNumber: ${preview[0].cnt}`);

        if (preview[0].cnt === 0) {
            console.log('Nothing to do.');
            return;
        }

        // Match each NULL-orderNumber order to a shopify_shipment by:
        //   - same clientId (via shopify_shops.pathxpress_client_id)
        //   - creation time within ±2 minutes
        // Uses UPDATE with INNER JOIN — only updates rows that have exactly one match.
        const [result] = await db.execute(`
            UPDATE orders o
            INNER JOIN (
                SELECT
                    s.shop_order_name,
                    sh.pathxpress_client_id,
                    s.created_at
                FROM shopify_shipments s
                INNER JOIN shopify_shops sh ON sh.shop_domain = s.shop_domain
                WHERE sh.pathxpress_client_id IS NOT NULL
            ) AS sm ON (
                sm.pathxpress_client_id = o.clientId
                AND sm.created_at BETWEEN DATE_SUB(o.createdAt, INTERVAL 2 MINUTE)
                                      AND DATE_ADD(o.createdAt, INTERVAL 2 MINUTE)
            )
            SET o.orderNumber = sm.shop_order_name
            WHERE o.orderNumber IS NULL
        `);

        console.log(`Updated ${result.affectedRows} order(s) with orderNumber.`);

        // Verify
        const [remaining] = await db.execute(`SELECT COUNT(*) AS cnt FROM orders WHERE orderNumber IS NULL`);
        console.log(`Orders still with NULL orderNumber after update: ${remaining[0].cnt}`);

        if (remaining[0].cnt > 0) {
            // Show which ones couldn't be matched
            const [unmatched] = await db.execute(`
                SELECT id, clientId, waybillNumber, createdAt
                FROM orders
                WHERE orderNumber IS NULL
                LIMIT 20
            `);
            console.log('Unmatched orders (no shopify_shipment within ±2 min):');
            console.table(unmatched);
        }

    } catch (err) {
        console.error('Error:', err);
    } finally {
        await db.end();
    }
}

run();
