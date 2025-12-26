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

async function addMissingColumns() {
    const columnsToAdd = [
        {
            name: 'shopify_fulfillment_id',
            sql: 'ALTER TABLE shopify_shipments ADD COLUMN shopify_fulfillment_id VARCHAR(100) DEFAULT NULL'
        }
    ];

    for (const col of columnsToAdd) {
        try {
            await db.execute(col.sql);
            console.log(`✅ Added column: ${col.name}`);
        } catch (err) {
            if (err.code === 'ER_DUP_FIELDNAME') {
                console.log(`ℹ️ Column ${col.name} already exists`);
            } else {
                console.log(`⚠️ Error adding ${col.name}:`, err.message);
            }
        }
    }

    await db.end();
    console.log("Done!");
}

addMissingColumns();
