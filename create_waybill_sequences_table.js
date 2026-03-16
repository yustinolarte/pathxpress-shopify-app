// Script para crear la tabla waybill_sequences
// Ejecutar UNA VEZ: node create_waybill_sequences_table.js

import mysql from "mysql2/promise";
import dotenv from "dotenv";
dotenv.config();

const db = await mysql.createPool({
    host: process.env.DB_HOST,
    port: process.env.DB_PORT ? Number(process.env.DB_PORT) : 3306,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME,
});

await db.execute(`
    CREATE TABLE IF NOT EXISTS waybill_sequences (
        prefix VARCHAR(10) NOT NULL,
        last_seq INT NOT NULL DEFAULT 0,
        PRIMARY KEY (prefix)
    ) ENGINE=InnoDB
`);

console.log("✅ Tabla waybill_sequences creada correctamente.");

// Migrar el último valor existente en orders para no reiniciar desde 1
const year = new Date().getFullYear();
const prefix = `PX${year}`;
const [[row]] = await db.execute(
    `SELECT waybillNumber FROM orders WHERE waybillNumber LIKE ? ORDER BY id DESC LIMIT 1`,
    [`${prefix}%`]
);

if (row?.waybillNumber) {
    const suffix = row.waybillNumber.replace(prefix, "");
    const lastSeq = parseInt(suffix, 10);
    if (!isNaN(lastSeq)) {
        await db.execute(
            `INSERT INTO waybill_sequences (prefix, last_seq) VALUES (?, ?)
             ON DUPLICATE KEY UPDATE last_seq = GREATEST(last_seq, ?)`,
            [prefix, lastSeq, lastSeq]
        );
        console.log(`✅ Migrado último waybill: ${row.waybillNumber} → last_seq = ${lastSeq}`);
    }
} else {
    await db.execute(
        `INSERT IGNORE INTO waybill_sequences (prefix, last_seq) VALUES (?, 0)`,
        [prefix]
    );
    console.log(`✅ Secuencia iniciada en 0 para prefijo ${prefix}`);
}

process.exit(0);
