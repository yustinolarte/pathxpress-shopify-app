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

async function checkFreeShipping() {
    try {
        const [rows] = await db.execute(
            "SELECT shop_domain, free_shipping_threshold FROM shopify_shops"
        );
        console.log("Current free_shipping_threshold values:");
        console.log(rows);
    } catch (err) {
        console.error("Error:", err.message);
    } finally {
        await db.end();
    }
}

checkFreeShipping();
