// ======================
// IMPORTS Y CONFIG
// ======================
import mysql from "mysql2/promise";
import express from "express";
import dotenv from "dotenv";
import crypto from "crypto";
import querystring from "querystring";
import jwt from "jsonwebtoken";


dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// Pool de conexión a MySQL (Railway)
const db = mysql.createPool({
    host: process.env.DB_HOST,
    port: process.env.DB_PORT ? Number(process.env.DB_PORT) : 3306,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME,
});

// ======================
// HELPER: Verificar Session Token de Shopify
// ======================
function verifySessionToken(token) {
    try {
        // Decodificar sin verificar para obtener el header y ver el shop
        const decoded = jwt.decode(token, { complete: true });
        if (!decoded) {
            console.error("❌ Session token could not be decoded");
            return null;
        }

        // Verificar el token usando el API Secret como clave
        const verified = jwt.verify(token, process.env.SHOPIFY_API_SECRET, {
            algorithms: ['HS256']
        });

        // El payload contiene información del shop y usuario
        // iss: https://{shop}.myshopify.com/admin
        // dest: https://{shop}.myshopify.com
        // sub: user ID
        const shopDomain = verified.dest?.replace('https://', '').replace('http://', '') ||
            verified.iss?.replace('https://', '').replace('/admin', '').replace('http://', '');

        console.log("✅ Session token verified for shop:", shopDomain);

        return {
            shop: shopDomain,
            userId: verified.sub,
            exp: verified.exp,
            iss: verified.iss,
            dest: verified.dest
        };
    } catch (error) {
        console.error("❌ Session token verification failed:", error.message);
        return null;
    }
}

// Middleware para proteger rutas con Session Token
function requireSessionToken(req, res, next) {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        // Si no hay token, intentar con el método tradicional (para compatibilidad)
        return next();
    }

    const token = authHeader.split(' ')[1];
    const sessionData = verifySessionToken(token);

    if (!sessionData) {
        return res.status(401).json({ error: "Invalid session token" });
    }

    // Adjuntar datos de sesión al request
    req.shopifySession = sessionData;
    req.query.shop = sessionData.shop;
    next();
}

// ======================
// HELPER: Guardar shipment en MySQL (tabla shopify_shipments)
// ======================
async function saveShipmentToMySQL(shipment) {
    try {
        const [result] = await db.execute(
            `INSERT INTO shopify_shipments (
        shop_domain,
        shop_order_id,
        shop_order_name,
        consignee_name,
        consignee_phone,
        address_line1,
        city,
        country,
        total_weight_kg,
        cod_amount,
        currency,
        status
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [
                shipment.shopDomain,
                shipment.shopOrderId,
                shipment.shopOrderName,
                shipment.consigneeName,
                shipment.consigneePhone,
                shipment.addressLine1,
                shipment.city,
                shipment.country,
                shipment.totalWeightKg ?? null,
                shipment.codAmount ?? null,
                shipment.currency || null,
                shipment.status || "PENDING_PICKUP",
            ]
        );

        console.log("🗄️ Shipment saved to MySQL, id:", result.insertId);
    } catch (err) {
        console.error("⛔ Error saving shipment to MySQL:", err);
    }
}
// ======================
// HELPER: insertar también en tabla `orders` del portal
// ======================
async function saveShipmentToOrdersTable(shipment) {
    try {
        // 1. Generar Waybill Number
        // Buscamos el último que empiece por PX2025...
        const [rows] = await db.execute(
            "SELECT waybillNumber FROM orders WHERE waybillNumber LIKE 'PX2025%' ORDER BY id DESC LIMIT 1"
        );

        let nextSequence = 1;
        if (rows.length > 0 && rows[0].waybillNumber) {
            const lastWaybill = rows[0].waybillNumber;
            // Asumiendo formato PX2025xxxxxx
            // Quitamos 'PX2025' y parseamos el resto
            const suffix = lastWaybill.replace("PX2025", "");
            const seq = parseInt(suffix, 10);
            if (!isNaN(seq)) {
                nextSequence = seq + 1;
            }
        }

        // Pad con ceros, ej: 00001
        const sequenceStr = nextSequence.toString().padStart(5, '0');
        const newWaybillNumber = `PX2025${sequenceStr}`;

        console.log("🔢 Generated Waybill:", newWaybillNumber);

        const [result] = await db.execute(
            `INSERT INTO orders (
        clientId,
        orderNumber,
        waybillNumber,
        shipperName,
        shipperAddress,
        shipperCity,
        shipperCountry,
        shipperPhone,
        customerName,
        customerPhone,
        address,
        city,
        emirate,
        postalCode,
        destinationCountry,
        pieces,
        weight,
        volumetricWeight,
        length,
        width,
        height,
        serviceType,
        specialInstructions,
        codRequired,
        codAmount,
        codCurrency,
        pickupDate,
        deliveryDateEstimated,
        deliveryDateReal,
        status,
        lastStatusUpdate,
        latitude,
        longitude,
        timeWindowStart,
        timeWindowEnd,
        priorityLevel,
        routeBatchId,
        createdAt,
        updatedAt
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [
                // client / identificación
                shipment.clientId,
                shipment.shopOrderName,       // orderNumber (ej: #1001)
                newWaybillNumber,             // waybillNumber generado

                // shipper
                shipment.shipperName,
                shipment.shipperAddress,
                shipment.shipperCity,
                shipment.shipperCountry,
                shipment.shipperPhone,

                // customer / destino
                shipment.consigneeName,
                shipment.consigneePhone,
                shipment.addressLine1,
                shipment.city,
                shipment.emirate,
                shipment.postalCode,
                shipment.country,

                // bultos / pesos / dimensiones
                shipment.pieces,
                shipment.totalWeightKg || 0,
                shipment.volumetricWeight || 0,
                shipment.length || 15,
                shipment.width || 15,
                shipment.height || 15,

                // servicio
                shipment.serviceType || "DOM",
                shipment.specialInstructions || "",

                // COD
                shipment.codRequired ? 1 : 0,
                shipment.codAmount || 0,
                shipment.codCurrency || "AED",

                // fechas y estado
                shipment.pickupDate
                    ? new Date(shipment.pickupDate)
                    : new Date(),
                null, // deliveryDateEstimated
                null, // deliveryDateReal
                shipment.status || "PENDING_PICKUP",
                new Date(), // lastStatusUpdate

                // geolocalización / ventana horaria / prioridad / rutas
                null, // latitude
                null, // longitude
                null, // timeWindowStart
                null, // timeWindowEnd
                0,    // priorityLevel
                null, // routeBatchId

                // timestamps
                shipment.createdAt
                    ? new Date(shipment.createdAt)
                    : new Date(),
                shipment.updatedAt
                    ? new Date(shipment.updatedAt)
                    : new Date(),
            ]
        );

        const insertedOrderId = result.insertId;
        console.log("📥 Shipment inserted into `orders` table, id:", insertedOrderId);

        // 2. Si tiene COD, crear registro en codRecords
        if (shipment.codRequired && shipment.codAmount > 0) {
            try {
                await db.execute(
                    `INSERT INTO codRecords (
                        shipmentId,
                        codAmount,
                        codCurrency,
                        status,
                        createdAt,
                        updatedAt
                    ) VALUES (?, ?, ?, ?, ?, ?)`,
                    [
                        insertedOrderId,
                        shipment.codAmount,
                        shipment.codCurrency || "AED",
                        "pending_collection", // Estado inicial
                        new Date(),
                        new Date()
                    ]
                );
                console.log("💰 COD record created for order:", insertedOrderId);
            } catch (codErr) {
                console.error("⛔ Error creating COD record:", codErr);
            }
        }
    } catch (err) {
        console.error("⛔ Error saving to `orders` table:", err);
    }
}

// ======================
// HELPER: Guardar/Actualizar tienda en DB
// ======================
async function saveShopToDB(shopDomain, accessToken, shopData) {
    try {
        const sql = `
            INSERT INTO shopify_shops (
                shop_domain, access_token, shop_name, email, phone,
                address1, address2, city, province, country, zip
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON DUPLICATE KEY UPDATE
                access_token = VALUES(access_token),
                shop_name = VALUES(shop_name),
                email = VALUES(email),
                phone = VALUES(phone),
                address1 = VALUES(address1),
                address2 = VALUES(address2),
                city = VALUES(city),
                province = VALUES(province),
                country = VALUES(country),
                zip = VALUES(zip),
                updated_at = CURRENT_TIMESTAMP
        `;
        await db.execute(sql, [
            shopDomain,
            accessToken,
            shopData.name,
            shopData.email,
            shopData.phone,
            shopData.address1,
            shopData.address2,
            shopData.city,
            shopData.province,
            shopData.country,
            shopData.zip
        ]);
        console.log(`💾 Shop ${shopDomain} saved/updated in DB.`);
    } catch (err) {
        console.error("⛔ Error saving shop to DB:", err);
    }
}

// ======================
// HELPER: Obtener tienda de DB
// ======================
async function getShopFromDB(shopDomain) {
    try {
        const [rows] = await db.execute(
            "SELECT * FROM shopify_shops WHERE shop_domain = ?",
            [shopDomain]
        );
        return rows[0] || null;
    } catch (err) {
        console.error("⛔ Error getting shop from DB:", err);
        return null;
    }
}

// Tokens en memoria por tienda
const shopsTokens = {}; // { "tienda.myshopify.com": "ACCESS_TOKEN" }

// Mapeo tienda Shopify -> cliente del portal
// YA NO USAMOS HARDCODED MAPPING. SE USA DB (shopify_shops.pathxpress_client_id)


// ======================
// HELPER: Verify Shopify Webhook HMAC
// ======================
function verifyShopifyWebhook(req, res, next) {
    const hmac = req.headers["x-shopify-hmac-sha256"];
    const shop = req.headers["x-shopify-shop-domain"];

    if (!hmac || !shop) {
        console.warn("⚠️ Webhook missing HMAC or Shop header");
        return res.status(401).send("Unauthorized");
    }

    try {
        // req.body must be a Buffer (raw) at this point
        const generatedHash = crypto
            .createHmac("sha256", process.env.SHOPIFY_API_SECRET)
            .update(req.body)
            .digest("base64");

        if (generatedHash !== hmac) {
            console.error(`⛔ HMAC Verification Failed!`);
            console.error(`   Shop: ${shop}`);
            console.error(`   Received HMAC: ${hmac}`);
            console.error(`   Calculated:    ${generatedHash}`);
            return res.status(401).send("Unauthorized: Invalid HMAC");
        }

        next();
    } catch (e) {
        console.error("⛔ Error verifying HMAC:", e);
        return res.status(500).send("Server Error");
    }
}

// ======================
// 1) WEBHOOKS (First, before express.json())
// ======================

// Middleware chain for webhooks: Raw Body -> HMAC Verification
// Middleware chain for webhooks: Raw Body -> HMAC Verification
const webhookMiddleware = [
    express.raw({ type: "*/*" }), // Capture all content types as Buffer
    verifyShopifyWebhook
];

// --- GDPR / Mandatory Webhooks (Unified Endpoint for shopify.app.toml) ---
app.post("/webhooks/shopify", webhookMiddleware, (req, res) => {
    const topic = req.headers["x-shopify-topic"];
    const shop = req.headers["x-shopify-shop-domain"];

    console.log(`🔒 GDPR Webhook received - Topic: ${topic}, Shop: ${shop}`);
    console.log("Headers:", JSON.stringify(req.headers, null, 2));
    console.log("Body:", req.body.toString());

    switch (topic) {
        case "customers/data_request":
            console.log("📋 Processing Customer Data Request");
            // Here you would collect and return customer data if you store any
            break;
        case "customers/redact":
            console.log("🗑️ Processing Customer Redact Request");
            // Here you would delete customer data if you store any
            break;
        case "shop/redact":
            console.log("🏪 Processing Shop Redact Request");
            // Here you would delete shop data after uninstall (48 hours later)
            break;
        default:
            console.log(`⚠️ Unknown GDPR topic: ${topic}`);
    }

    res.status(200).send();
});

// --- GDPR / Mandatory Webhooks (Legacy individual endpoints) ---
app.post("/webhooks/shopify/customers/data_request", webhookMiddleware, (req, res) => {
    console.log("🔒 GDPR: Customer Data Request received");
    console.log("Headers:", JSON.stringify(req.headers, null, 2));
    console.log("Body:", req.body.toString());
    res.status(200).send();
});

app.post("/webhooks/shopify/customers/redact", webhookMiddleware, (req, res) => {
    console.log("🔒 GDPR: Customer Redact received");
    console.log("Headers:", JSON.stringify(req.headers, null, 2));
    console.log("Body:", req.body.toString());
    res.status(200).send();
});

app.post("/webhooks/shopify/shop/redact", webhookMiddleware, (req, res) => {
    console.log("🔒 GDPR: Shop Redact received");
    console.log("Headers:", JSON.stringify(req.headers, null, 2));
    console.log("Body:", req.body.toString());
    res.status(200).send();
});

// --- Order Webhook ---
app.post(
    "/webhooks/shopify/orders",
    webhookMiddleware,
    async (req, res) => {
        const shop = req.headers["x-shopify-shop-domain"];

        try {
            const bodyString = req.body.toString("utf8");
            const order = JSON.parse(bodyString);

            console.log("📦 New ORDER from Shopify:", order.name);

            // 1. Obtener info de la tienda de la DB para llenar el Shipper
            const shopData = await getShopFromDB(shop);

            // --- IDEMPOTENCIA (Evitar duplicados) ---
            // Verificar si ya procesamos esta orden (por ID de Shopify)
            const [existing] = await db.execute(
                "SELECT id FROM shopify_shipments WHERE shop_domain = ? AND shop_order_id = ?",
                [shop, order.id]
            );

            if (existing.length > 0) {
                console.log(`⚠️ Order ${order.name} already exists in DB. Ignoring duplicate.`);
                return res.sendStatus(200);
            }

            // --- FILTRADO DE ÓRDENES ---
            if (shopData) {
                const autoSync = shopData.auto_sync !== 0;
                const requiredTag = shopData.sync_tag;
                const orderTags = (order.tags || "").split(",").map(t => t.trim());

                // Caso A: AutoSync desactivado y NO tiene el tag requerido
                if (!autoSync && requiredTag && !orderTags.includes(requiredTag)) {
                    console.log(`🚫 Order ${order.name} ignored: AutoSync OFF and missing tag '${requiredTag}'`);
                    return res.sendStatus(200);
                }

                // Caso B: AutoSync activado, pero hay un tag requerido EXCLUYENTE? 
                // Normalmente si pones un tag, es para filtrar.
                // Lógica: Si hay tag definido, DEBE tenerlo, salvo que AutoSync sea "Todo" y el tag sea opcional.
                // Interpretación común:
                // - Checkbox ON: Sincroniza todo (ignora tag field salvo que quieras lógica compleja).
                // - Checkbox OFF: Solo sincroniza si tiene el tag.
                // Vamos a usar esa lógica simple:

                if (!autoSync) {
                    // Si no es auto, DEBE tener el tag
                    if (!requiredTag || !orderTags.includes(requiredTag)) {
                        console.log(`🚫 Order ${order.name} ignored: Requires tag '${requiredTag}'`);
                        return res.sendStatus(200);
                    }
                } else {
                    // Si es auto, sincroniza todo. 
                    // (Opcional: Podrías querer que "Auto" signifique "Todo", o "Todo lo que coincida con Tag si existe")
                    // Dejémoslo como: Auto = Todo.
                }
            }
            // ---------------------------

            const shipment = orderToShipment(order, shop, shopData);

            console.log("🚚 Shipment ready to save to MySQL:");
            console.dir(shipment, { depth: null });

            // 1) log / auditoría Shopify
            await saveShipmentToMySQL(shipment);

            // 2) insertar en tabla principal orders
            await saveShipmentToOrdersTable(shipment);

        } catch (e) {
            console.log("⚠️ Error processing webhook order:", e);

            // GUARDAR EN COLA DE REINTENTOS
            try {
                const bodyString = req.body.toString("utf8"); // Recuperar body original
                await db.execute(`
                    INSERT INTO webhook_retries (shop_domain, payload, error_message)
                    VALUES (?, ?, ?)
                `, [shop, bodyString, e.message]);
                console.log("🛡️ Order saved to retry queue.");
            } catch (dbErr) {
                console.error("⛔ CRITICAL Error saving to retries:", dbErr);
            }
        }

        res.sendStatus(200);
    }
);




// ======================
// 2) AHORA SÍ, JSON PARA EL RESTO
// ======================
app.use(express.json());

// ======================
// 3) RUTA SIMPLE
// ======================
app.get("/", (req, res) => {
    res.send("PATHXPRESS Shopify App is running ✅");
});
// ======================
// 4) PANTALLA PRINCIPAL /app
// ======================
app.get("/app", requireSessionToken, async (req, res) => {
    // Obtener shop de session token, query params, o header
    const shop = req.shopifySession?.shop ||
        req.query.shop ||
        req.headers["x-shopify-shop-domain"] || "";

    if (!shop) {
        return res.status(400).send("Could not detect the shop.");
    }

    const isConnected = Boolean(shopsTokens[shop]);

    // Obtener configuración actual de la DB
    let currentClientId = "";
    let currentAutoSync = true;
    let currentSyncTag = "";
    let currentServiceType = "DOM"; // Default service type
    let freeShippingDOM = ""; // Umbral para envío gratis Standard
    let freeShippingExpress = ""; // Umbral para envío gratis Express
    let shipmentsRows = "<tr><td colspan='5'>No recent shipments.</td></tr>";
    let metrics = { todayCount: 0, activeCount: 0, pendingCod: 0 };
    let shopData = null;

    if (isConnected) {
        // 1. Obtener datos de la tienda (Client ID)
        shopData = await getShopFromDB(shop);
        if (shopData) {
            currentClientId = shopData.pathxpress_client_id;
            currentAutoSync = shopData.auto_sync !== 0; // MySQL boolean is 0/1
            currentServiceType = shopData.default_service_type || "DOM";
            currentSyncTag = shopData.sync_tag || "";
            freeShippingDOM = shopData.free_shipping_threshold_dom || "";
            freeShippingExpress = shopData.free_shipping_threshold_express || "";
        }

        // 2. Obtener métricas y envíos
        try {
            const [metricRows] = await db.execute(`
                SELECT 
                    COUNT(CASE WHEN DATE(o.createdAt) = CURDATE() THEN 1 END) as todayCount,
                    COUNT(CASE WHEN o.status NOT IN ('DELIVERED', 'CANCELLED', 'RETURNED') THEN 1 END) as activeCount,
                    SUM(CASE 
                        WHEN o.codRequired = 1 
                        AND o.status NOT IN ('DELIVERED', 'CANCELLED', 'RETURNED') 
                        THEN o.codAmount 
                        ELSE 0 
                    END) as pendingCod
                FROM shopify_shipments s
                JOIN orders o ON (o.orderNumber = s.shop_order_name) 
                WHERE s.shop_domain = ?
            `, [shop]);

            if (metricRows.length > 0) {
                metrics = metricRows[0];
            }

            const [rows] = await db.execute(`
                SELECT 
                    s.shop_order_name, 
                    o.*
                FROM shopify_shipments s
                JOIN orders o ON (o.orderNumber = s.shop_order_name)
                WHERE s.shop_domain = ?
                ORDER BY s.id DESC
                LIMIT 20
            `, [shop]);

            if (rows.length > 0) {
                shipmentsRows = rows.map(row => {
                    const shipmentData = JSON.stringify({
                        waybillNumber: row.waybillNumber,
                        shipperName: row.shipperName,
                        shipperAddress: row.shipperAddress,
                        shipperCity: row.shipperCity,
                        shipperCountry: row.shipperCountry,
                        shipperPhone: row.shipperPhone,
                        customerName: row.customerName,
                        customerPhone: row.customerPhone,
                        address: row.address,
                        city: row.city,
                        emirate: row.emirate,
                        destinationCountry: row.destinationCountry,
                        pieces: row.pieces,
                        weight: row.weight,
                        length: row.length,
                        width: row.width,
                        height: row.height,
                        serviceType: row.serviceType,
                        status: row.status,
                        createdAt: row.createdAt,
                        codRequired: row.codRequired,
                        codAmount: row.codAmount,
                        codCurrency: row.codCurrency
                    }).replace(/"/g, '&quot;');

                    return `
                    <tr>
                        <td><strong style="color: var(--text-primary);">${row.shop_order_name}</strong></td>
                        <td><span style="color: var(--blue-electric); font-weight: 600;">${row.waybillNumber || '---'}</span></td>
                        <td>
                            <span class="badge badge-status">
                                ${row.status}
                            </span>
                        </td>
                        <td>${new Date(row.createdAt).toLocaleDateString()}</td>
                        <td>
                            ${row.waybillNumber
                            ? `<button class="print-btn" onclick='generateWaybillPDF(${shipmentData})'><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="margin-right:4px;vertical-align:middle;"><polyline points="6 9 6 2 18 2 18 9"></polyline><path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"></path><rect x="6" y="14" width="12" height="8"></rect></svg>Print Label</button>`
                            : '<span style="color: var(--text-muted);">Pending</span>'
                        }
                        </td>
                    </tr>
                `}).join("");
            }
        } catch (err) {
            console.error("Error getting shipments for dashboard:", err);
        }
    }

    res.send(`
    <html>
      <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <title>PATHXPRESS Portal</title>
        <link rel="preconnect" href="https://fonts.googleapis.com">
        <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=Poppins:wght@500;600;700&display=swap" rel="stylesheet">
        <script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js"></script>
        <script src="https://cdn.jsdelivr.net/npm/jsbarcode@3.11.5/dist/JsBarcode.all.min.js"></script>
        <script src="https://cdn.jsdelivr.net/npm/qrcode@1.5.3/build/qrcode.min.js"></script>
        <script src="https://unpkg.com/lucide@latest"></script>
        <style>
            :root {
                --bg-primary: #0A1128;
                --bg-card: #0F1A3B;
                --blue-electric: #2D6CF6;
                --red-accent: #E10600;
                --red-neon: #FF2E2E;
                --text-primary: #FFFFFF;
                --text-muted: #8A8F98;
                --border-color: rgba(255, 255, 255, 0.1);
            }
            
            * { box-sizing: border-box; margin: 0; padding: 0; }
            
            body { 
                font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; 
                padding: 25px; 
                color: var(--text-primary);
                background: linear-gradient(135deg, var(--bg-primary) 0%, var(--bg-card) 100%);
                min-height: 100vh;
                -webkit-font-smoothing: antialiased;
            }
            
            .card { 
                background: rgba(15, 26, 59, 0.6);
                backdrop-filter: blur(16px);
                -webkit-backdrop-filter: blur(16px);
                border: 1px solid var(--border-color);
                border-radius: 16px; 
                padding: 24px; 
                margin-bottom: 20px; 
                box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
                transition: transform 0.3s ease, box-shadow 0.3s ease;
            }
            
            .card:hover {
                transform: translateY(-2px);
                box-shadow: 0 12px 40px rgba(0, 0, 0, 0.4), 0 0 20px rgba(45, 108, 246, 0.1);
            }
            
            h1 { 
                font-family: 'Poppins', sans-serif;
                font-size: 28px; 
                font-weight: 700;
                margin-bottom: 10px; 
                background: linear-gradient(135deg, var(--blue-electric), var(--red-neon));
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                background-clip: text;
            }
            
            h2 { 
                font-family: 'Poppins', sans-serif;
                font-size: 18px; 
                font-weight: 600;
                margin-bottom: 15px;
                color: var(--text-primary);
                display: flex;
                align-items: center;
                gap: 8px;
            }
            
            h3 {
                font-family: 'Poppins', sans-serif;
                font-weight: 600;
                color: var(--text-primary);
            }
            
            p { color: var(--text-muted); line-height: 1.6; }
            
            label { 
                display: block; 
                margin-bottom: 8px; 
                font-weight: 500; 
                color: var(--text-primary);
                font-size: 14px;
            }
            
            input[type="text"], input[type="number"], select { 
                width: 100%; 
                padding: 12px 16px; 
                margin-bottom: 15px; 
                border: 1px solid var(--border-color); 
                border-radius: 10px; 
                background: rgba(255, 255, 255, 0.05);
                color: var(--text-primary);
                font-size: 14px;
                transition: all 0.3s ease;
            }
            
            input[type="text"]:focus, input[type="number"]:focus, select:focus { 
                outline: none;
                border-color: var(--blue-electric);
                box-shadow: 0 0 0 3px rgba(45, 108, 246, 0.2);
                background: rgba(255, 255, 255, 0.08);
            }
            
            input::placeholder { color: var(--text-muted); }
            
            button { 
                background: linear-gradient(135deg, var(--blue-electric), #1e5ad4);
                color: white; 
                border: none; 
                padding: 12px 24px; 
                border-radius: 10px; 
                cursor: pointer; 
                font-weight: 600;
                font-size: 14px;
                transition: all 0.3s ease;
                box-shadow: 0 4px 15px rgba(45, 108, 246, 0.3);
            }
            
            button:hover { 
                transform: translateY(-2px);
                box-shadow: 0 6px 20px rgba(45, 108, 246, 0.4);
            }
            
            button:active {
                transform: translateY(0);
            }
            
            .btn-secondary {
                background: linear-gradient(135deg, #5c6ac4, #4959bd);
            }
            
            .btn-danger {
                background: linear-gradient(135deg, var(--red-accent), #c20500);
                box-shadow: 0 4px 15px rgba(225, 6, 0, 0.3);
            }
            
            .btn-danger:hover {
                box-shadow: 0 6px 20px rgba(225, 6, 0, 0.4);
            }
            
            .metric-card { 
                flex: 1; 
                background: rgba(45, 108, 246, 0.1);
                backdrop-filter: blur(10px);
                padding: 20px; 
                border-radius: 14px; 
                text-align: center; 
                border: 1px solid rgba(45, 108, 246, 0.2);
                transition: all 0.3s ease;
            }
            
            .metric-card:hover {
                background: rgba(45, 108, 246, 0.15);
                border-color: rgba(45, 108, 246, 0.3);
                transform: translateY(-3px);
            }
            
            .metric-val { 
                font-family: 'Poppins', sans-serif;
                font-size: 32px; 
                font-weight: 700; 
                color: var(--text-primary); 
                margin-top: 8px;
                background: linear-gradient(135deg, var(--text-primary), var(--blue-electric));
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                background-clip: text;
            }
            
            .metric-label { 
                font-size: 11px; 
                color: var(--text-muted); 
                text-transform: uppercase; 
                letter-spacing: 1px;
                font-weight: 500;
            }
            
            .status-connected {
                display: inline-flex;
                align-items: center;
                gap: 6px;
                color: #22c55e;
                font-weight: 600;
                font-size: 14px;
            }
            
            .status-connected::before {
                content: '';
                width: 10px;
                height: 10px;
                background: #22c55e;
                border-radius: 50%;
                box-shadow: 0 0 10px #22c55e;
                animation: pulse 2s infinite;
            }
            
            .status-disconnected {
                display: inline-flex;
                align-items: center;
                gap: 6px;
                color: var(--red-neon);
                font-weight: 600;
                font-size: 14px;
            }
            
            .status-disconnected::before {
                content: '';
                width: 10px;
                height: 10px;
                background: var(--red-neon);
                border-radius: 50%;
            }
            
            @keyframes pulse {
                0%, 100% { opacity: 1; transform: scale(1); }
                50% { opacity: 0.7; transform: scale(1.1); }
            }
            
            table { 
                width: 100%; 
                border-collapse: separate;
                border-spacing: 0;
                font-size: 14px;
            }
            
            thead tr {
                background: rgba(45, 108, 246, 0.1);
            }
            
            th {
                padding: 14px 12px;
                text-align: left;
                font-weight: 600;
                color: var(--text-primary);
                border-bottom: 1px solid var(--border-color);
                font-size: 12px;
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }
            
            td {
                padding: 14px 12px;
                border-bottom: 1px solid var(--border-color);
                color: var(--text-muted);
            }
            
            tbody tr {
                transition: background 0.2s ease;
            }
            
            tbody tr:hover {
                background: rgba(45, 108, 246, 0.05);
            }
            
            .badge {
                display: inline-block;
                padding: 4px 10px;
                border-radius: 20px;
                font-size: 11px;
                font-weight: 600;
                text-transform: uppercase;
                letter-spacing: 0.3px;
            }
            
            .badge-status {
                background: rgba(45, 108, 246, 0.2);
                color: var(--blue-electric);
                border: 1px solid rgba(45, 108, 246, 0.3);
            }
            
            .badge-success {
                background: rgba(34, 197, 94, 0.2);
                color: #22c55e;
                border: 1px solid rgba(34, 197, 94, 0.3);
            }
            
            .badge-warning {
                background: rgba(245, 158, 11, 0.2);
                color: #f59e0b;
                border: 1px solid rgba(245, 158, 11, 0.3);
            }
            
            .print-btn {
                background: none;
                border: none;
                padding: 6px 12px;
                color: var(--blue-electric);
                font-weight: 600;
                cursor: pointer;
                display: inline-flex;
                align-items: center;
                gap: 4px;
                transition: all 0.2s ease;
                box-shadow: none;
            }
            
            .print-btn:hover {
                color: var(--text-primary);
                background: rgba(45, 108, 246, 0.1);
                border-radius: 6px;
                transform: none;
                box-shadow: none;
            }
            
            .settings-section {
                background: rgba(255, 255, 255, 0.03);
                border-radius: 12px;
                padding: 16px;
                margin-bottom: 16px;
                border: 1px solid var(--border-color);
            }
            
            .checkbox-wrapper {
                display: flex;
                align-items: center;
                gap: 10px;
            }
            
            input[type="checkbox"] {
                width: 18px;
                height: 18px;
                accent-color: var(--blue-electric);
                cursor: pointer;
            }
            
            .helper-text {
                font-size: 12px;
                color: var(--text-muted);
                margin-top: 4px;
                margin-left: 28px;
            }
            
            .feedback-box {
                margin-top: 10px;
                padding: 12px 16px;
                border-radius: 10px;
                font-size: 14px;
            }
            
            .feedback-success {
                background: rgba(34, 197, 94, 0.15);
                border: 1px solid rgba(34, 197, 94, 0.3);
                color: #22c55e;
            }
            
            .feedback-error {
                background: rgba(239, 68, 68, 0.15);
                border: 1px solid rgba(239, 68, 68, 0.3);
                color: #ef4444;
            }
            
            .feedback-warning {
                background: rgba(245, 158, 11, 0.15);
                border: 1px solid rgba(245, 158, 11, 0.3);
                color: #f59e0b;
            }
            
            .feedback-info {
                background: rgba(45, 108, 246, 0.15);
                border: 1px solid rgba(45, 108, 246, 0.3);
                color: var(--blue-electric);
            }
            
            .grid-2 {
                display: grid;
                grid-template-columns: 1fr 1fr;
                gap: 15px;
            }
            
            @media (max-width: 768px) {
                .grid-2 { grid-template-columns: 1fr; }
                body { padding: 15px; }
                .card { padding: 16px; }
            }
            
            /* Scrollbar styling */
            ::-webkit-scrollbar { width: 8px; }
            ::-webkit-scrollbar-track { background: var(--bg-primary); }
            ::-webkit-scrollbar-thumb { background: var(--blue-electric); border-radius: 4px; }
            ::-webkit-scrollbar-thumb:hover { background: var(--red-neon); }
            
            /* Icon styling for Lucide Icons */
            .icon { 
                display: inline-flex; 
                align-items: center;
                justify-content: center;
                margin-right: 8px;
                vertical-align: middle;
            }
            .icon svg {
                width: 20px;
                height: 20px;
                stroke-width: 2;
            }
            .icon-sm svg {
                width: 16px;
                height: 16px;
            }
            .icon-lg svg {
                width: 24px;
                height: 24px;
            }
            h1 .icon svg, h2 .icon svg {
                width: 24px;
                height: 24px;
            }
            button .icon {
                margin-right: 6px;
            }
            button .icon svg {
                width: 16px;
                height: 16px;
            }
        </style>
        <script>
            // City code mapping for UAE cities
            function getCityCode(city) {
                if (!city) return 'UAE';
                const cityLower = city.toLowerCase().trim();

                // UAE Cities
                if (cityLower.includes('dubai') || cityLower === 'dxb') return 'DXB';
                if (cityLower.includes('sharjah') || cityLower === 'shj') return 'SHJ';
                if (cityLower.includes('abu dhabi') || cityLower.includes('abudhabi')) return 'AUH';
                if (cityLower.includes('ajman')) return 'AJM';
                if (cityLower.includes('fujairah') || cityLower.includes('fujeirah')) return 'FUJ';
                if (cityLower.includes('ras al') || cityLower.includes('rak')) return 'RAK';
                if (cityLower.includes('umm al') || cityLower.includes('uaq')) return 'UAQ';
                if (cityLower.includes('al ain')) return 'AAN';

                // Default: first 3 letters uppercase
                return city.substring(0, 3).toUpperCase();
            }

            // Encode package data for route scanning QR
            function encodePackageData(shipment) {
                const data = {
                    w: shipment.waybillNumber,
                    n: shipment.customerName,
                    p: shipment.customerPhone,
                    a: (shipment.address || '').substring(0, 50),
                    c: shipment.city,
                    kg: shipment.weight,
                    s: shipment.serviceType,
                    cod: shipment.codRequired ? shipment.codAmount : '0',
                    pcs: shipment.pieces
                };
                return btoa(JSON.stringify(data));
            }

            async function generateWaybillPDF(shipment) {
                const { jsPDF } = window.jspdf;
                
                // Standard shipping label (100mm x 150mm)
                const pdf = new jsPDF({
                    orientation: 'portrait',
                    unit: 'mm',
                    format: [100, 150],
                });

                const pageWidth = 100;
                const pageHeight = 150;
                const margin = 3;
                const contentWidth = pageWidth - (margin * 2);

                // Black and white colors only
                const black = '#000000';
                const white = '#FFFFFF';

                // Black border
                pdf.setDrawColor(black);
                pdf.setLineWidth(1);
                pdf.rect(1, 1, pageWidth - 2, pageHeight - 2);

                let y = margin + 2;

                // ===== HEADER: Logo =====
                pdf.setFontSize(18);
                pdf.setFont('helvetica', 'bold');
                pdf.setTextColor(black);
                pdf.text('PATHXPRESS', margin, y + 8);

                // Date on right
                pdf.setFontSize(7);
                pdf.setFont('helvetica', 'normal');
                const dateStr = new Date(shipment.createdAt || new Date()).toLocaleDateString('en-GB');
                pdf.text(dateStr, pageWidth - margin, y + 4, { align: 'right' });
                pdf.setFontSize(8);
                pdf.setFont('helvetica', 'bold');
                pdf.text(shipment.waybillNumber, pageWidth - margin, y + 9, { align: 'right' });

                y += 16;

                // Separator line
                pdf.setDrawColor(black);
                pdf.setLineWidth(0.5);
                pdf.line(margin, y, pageWidth - margin, y);

                // ===== SHIPPER (FROM) Section =====
                y += 2;

                pdf.setFontSize(6);
                pdf.setFont('helvetica', 'bold');
                pdf.setTextColor(black);
                pdf.text('FROM:', margin, y + 3);

                pdf.setFontSize(8);
                pdf.text(shipment.shipperName || '', margin + 11, y + 3);

                pdf.setFontSize(7);
                pdf.setFont('helvetica', 'normal');
                pdf.text((shipment.shipperPhone || '') + ' | ' + (shipment.shipperCity || ''), margin + 11, y + 7);

                y += 10;
                pdf.line(margin, y, pageWidth - margin, y);

                // ===== CONSIGNEE (TO) Section =====
                y += 2;

                pdf.setFontSize(6);
                pdf.setFont('helvetica', 'bold');
                pdf.text('TO:', margin, y + 4);

                // Customer name (large and bold)
                pdf.setFontSize(13);
                pdf.text(shipment.customerName || '', margin + 7, y + 5);

                // Phone
                pdf.setFontSize(11);
                pdf.text(shipment.customerPhone || '', margin + 7, y + 11);

                // Address
                pdf.setFontSize(8);
                pdf.setFont('helvetica', 'normal');
                const addressLines = pdf.splitTextToSize(shipment.address || '', contentWidth - 35);
                pdf.text(addressLines.slice(0, 2), margin + 7, y + 16);

                // City (bold)
                pdf.setFont('helvetica', 'bold');
                pdf.text((shipment.city || '') + ', ' + (shipment.destinationCountry || 'UAE'), margin + 7, y + 24);

                // ROUTING CODE + QR (right side)
                const routingX = pageWidth - margin - 40;
                const cityCode = getCityCode(shipment.city);

                // City code box (black background)
                pdf.setFillColor(black);
                pdf.rect(routingX, y, 18, 22, 'F');

                pdf.setFontSize(16);
                pdf.setFont('helvetica', 'bold');
                pdf.setTextColor(white);
                pdf.text(cityCode, routingX + 9, y + 14, { align: 'center' });

                // Service type below city code
                pdf.setFontSize(8);
                const serviceType = shipment.serviceType === 'SDD' || shipment.serviceType === 'SAMEDAY' ? 'SDD' : 'DOM';
                pdf.text(serviceType, routingX + 9, y + 20, { align: 'center' });
                pdf.setTextColor(black);

                // QR Code with encoded package data (for route scanning)
                const qrSize = 20;
                const qrX = routingX + 20;

                try {
                    const packageData = encodePackageData(shipment);
                    const qrCanvas = document.createElement('canvas');
                    await QRCode.toCanvas(qrCanvas, packageData, { width: 200, margin: 0 });
                    pdf.addImage(qrCanvas.toDataURL('image/png'), 'PNG', qrX, y + 1, qrSize, qrSize);
                } catch (e) {
                    pdf.setDrawColor(black);
                    pdf.rect(qrX, y + 1, qrSize, qrSize);
                    pdf.setFontSize(5);
                    pdf.text('SCAN', qrX + qrSize / 2, y + qrSize / 2, { align: 'center' });
                }

                y += 28;
                pdf.setDrawColor(black);
                pdf.line(margin, y, pageWidth - margin, y);

                // ===== PACKAGE INFO + COD =====
                y += 2;

                // Info grid - 4 columns
                const colWidth = contentWidth / 4;

                // Pieces
                pdf.setDrawColor(black);
                pdf.setLineWidth(0.3);
                pdf.rect(margin, y, colWidth, 14);
                pdf.setFontSize(6);
                pdf.setFont('helvetica', 'normal');
                pdf.text('PCS', margin + colWidth / 2, y + 4, { align: 'center' });
                pdf.setFontSize(12);
                pdf.setFont('helvetica', 'bold');
                pdf.text((shipment.pieces || 1).toString(), margin + colWidth / 2, y + 11, { align: 'center' });

                // Weight
                pdf.rect(margin + colWidth, y, colWidth, 14);
                pdf.setFontSize(6);
                pdf.setFont('helvetica', 'normal');
                pdf.text('KG', margin + colWidth + colWidth / 2, y + 4, { align: 'center' });
                pdf.setFontSize(12);
                pdf.setFont('helvetica', 'bold');
                const weightVal = typeof shipment.weight === 'string' ? parseFloat(shipment.weight) : (shipment.weight || 0);
                pdf.text(weightVal.toFixed(1), margin + colWidth + colWidth / 2, y + 11, { align: 'center' });

                // Service Type
                pdf.rect(margin + colWidth * 2, y, colWidth, 14);
                pdf.setFontSize(6);
                pdf.setFont('helvetica', 'normal');
                pdf.text('SERVICE', margin + colWidth * 2 + colWidth / 2, y + 4, { align: 'center' });
                pdf.setFontSize(12);
                pdf.setFont('helvetica', 'bold');
                pdf.text(serviceType, margin + colWidth * 2 + colWidth / 2, y + 11, { align: 'center' });

                // COD or Prepaid
                pdf.rect(margin + colWidth * 3, y, colWidth, 14);

                if (shipment.codRequired && shipment.codAmount) {
                    // COD - black background
                    pdf.setFillColor(black);
                    pdf.rect(margin + colWidth * 3, y, colWidth, 14, 'F');
                    pdf.setFontSize(6);
                    pdf.setFont('helvetica', 'bold');
                    pdf.setTextColor(white);
                    pdf.text('COD', margin + colWidth * 3 + colWidth / 2, y + 4, { align: 'center' });
                    pdf.setFontSize(9);
                    const codAmount = parseFloat(shipment.codAmount).toFixed(0);
                    pdf.text(codAmount, margin + colWidth * 3 + colWidth / 2, y + 11, { align: 'center' });
                    pdf.setTextColor(black);
                } else {
                    pdf.setFontSize(6);
                    pdf.setFont('helvetica', 'normal');
                    pdf.text('STATUS', margin + colWidth * 3 + colWidth / 2, y + 4, { align: 'center' });
                    pdf.setFontSize(8);
                    pdf.setFont('helvetica', 'bold');
                    pdf.text('PREPAID', margin + colWidth * 3 + colWidth / 2, y + 11, { align: 'center' });
                }

                y += 16;

                // ===== SPECIAL INSTRUCTIONS =====
                if (shipment.specialInstructions && shipment.specialInstructions.trim()) {
                    pdf.setDrawColor(black);
                    pdf.setLineWidth(0.5);
                    pdf.rect(margin, y, contentWidth, 10);

                    pdf.setFontSize(6);
                    pdf.setFont('helvetica', 'bold');
                    pdf.text('NOTE:', margin + 2, y + 4);

                    pdf.setFontSize(7);
                    pdf.setFont('helvetica', 'normal');
                    const instrLines = pdf.splitTextToSize(shipment.specialInstructions, contentWidth - 15);
                    pdf.text(instrLines.slice(0, 1).join(' '), margin + 12, y + 4);

                    y += 12;
                }

                // ===== MAIN BARCODE (Large, High Quality) =====
                y = pageHeight - 35;

                pdf.setDrawColor(black);
                pdf.setLineWidth(0.3);
                pdf.line(margin, y - 2, pageWidth - margin, y - 2);

                try {
                    const canvas = document.createElement('canvas');
                    JsBarcode(canvas, shipment.waybillNumber, {
                        format: 'CODE128',
                        width: 3,
                        height: 60,
                        displayValue: false,
                        margin: 0,
                        background: '#FFFFFF',
                        lineColor: '#000000'
                    });
                    const barcodeUrl = canvas.toDataURL('image/png');
                    pdf.addImage(barcodeUrl, 'PNG', margin + 5, y, contentWidth - 10, 18);
                } catch (e) {
                    console.error('Barcode error:', e);
                }

                // Waybill number text (separate for clarity)
                pdf.setFontSize(14);
                pdf.setFont('helvetica', 'bold');
                pdf.setTextColor(black);
                pdf.text(shipment.waybillNumber, pageWidth / 2, y + 24, { align: 'center' });

                // Footer
                pdf.setFontSize(6);
                pdf.setFont('helvetica', 'normal');
                pdf.text('pathxpress.net  |  +971 522803433', pageWidth / 2, pageHeight - 4, { align: 'center' });

                // Save
                pdf.save('waybill-' + shipment.waybillNumber + '.pdf');
            }
        </script>
      </head>
      <body>
        <div class="card">
            <h1><i data-lucide="rocket" class="icon"></i>PATHXPRESS Portal</h1>
            <p>Connected shop: <strong style="color: var(--text-primary);">${shop}</strong></p>
            ${isConnected ? '<span class="status-connected">Connected</span>' : '<span class="status-disconnected">Disconnected</span>'}
        </div>

        ${isConnected
            ? `
              <div class="card">
                <div style="display:flex; gap:20px;">
                    <div class="metric-card">
                        <div class="metric-label">Shipments Today</div>
                        <div class="metric-val">${metrics.todayCount || 0}</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-label">Active Shipments</div>
                        <div class="metric-val">${metrics.activeCount || 0}</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-label">Pending COD</div>
                        <div class="metric-val">AED ${(metrics.pendingCod || 0).toLocaleString()}</div>
                    </div>
                </div>
              </div>

              <div class="card">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:15px;">
                    <h2 style="margin:0;"><i data-lucide="settings" class="icon"></i>General Settings</h2>
                    ${currentClientId ? `
                        <button type="button" id="editBtn" onclick="toggleEditMode()" class="btn-secondary">
                            <i data-lucide="pencil" class="icon"></i>Edit Settings
                        </button>
                    ` : ''}
                </div>
                
                <form action="/app/save-settings" method="POST" id="settingsForm">
                    <input type="hidden" name="shop" value="${shop}" />
                    
                    <fieldset id="settingsFieldset" ${currentClientId ? 'disabled' : ''} style="border:none; padding:0; margin:0;">
                    
                    <label for="clientId">PathXpress Client ID:</label>
                    <div style="display:flex; gap:10px; align-items:center;">
                        <input type="number" id="clientId" name="clientId" placeholder="Enter your Client ID" required value="${currentClientId || ''}" style="flex:1; margin-bottom:0;" onchange="validateClientId(this.value)" />
                        <button type="button" onclick="validateClientId(document.getElementById('clientId').value)" style="background:#5c6ac4; padding:10px 15px;">Verify</button>
                    </div>
                    <div id="clientFeedback" class="feedback-box feedback-info" style="display:none;"></div>
                    <script>
                        async function validateClientId(id) {
                            if (!id) return;
                            const feedback = document.getElementById('clientFeedback');
                            feedback.style.display = 'block';
                            feedback.className = 'feedback-box feedback-info';
                            feedback.innerHTML = '<i data-lucide="search" class="icon icon-sm"></i>Verifying...';
                            
                            // Timeout controller
                            const controller = new AbortController();
                            const timeoutId = setTimeout(() => controller.abort(), 10000);
                            
                            try {
                                const res = await fetch('/api/validate-client/' + id, {
                                    signal: controller.signal
                                });
                                clearTimeout(timeoutId);
                                const data = await res.json();
                                if (data.found) {
                                    feedback.className = 'feedback-box feedback-success';
                                    feedback.innerHTML = '<i data-lucide="check-circle" class="icon icon-sm"></i><strong>' + data.companyName + '</strong> (Contact: ' + (data.contactName || 'N/A') + ')';
                                    lucide.createIcons();
                                } else {
                                    feedback.className = 'feedback-box feedback-error';
                                    feedback.innerHTML = '<i data-lucide="x-circle" class="icon icon-sm"></i>Client ID not found. Please check and try again.';
                                    lucide.createIcons();
                                }
                            } catch (e) {
                                clearTimeout(timeoutId);
                                feedback.className = 'feedback-box feedback-warning';
                                if (e.name === 'AbortError') {
                                    feedback.innerHTML = '<i data-lucide="clock" class="icon icon-sm"></i>Verification timed out. Will save anyway.';
                                } else {
                                    feedback.innerHTML = '<i data-lucide="alert-triangle" class="icon icon-sm"></i>Could not verify. Will save anyway.';
                                }
                                lucide.createIcons();
                            }
                        }
                        // Auto-validate if there's a value on load
                        if (document.getElementById('clientId').value) {
                            validateClientId(document.getElementById('clientId').value);
                        }
                        
                        // Toggle edit mode
                        function toggleEditMode() {
                            const fieldset = document.getElementById('settingsFieldset');
                            const editBtn = document.getElementById('editBtn');
                            const saveBtn = document.getElementById('saveBtn');
                            
                            if (fieldset.disabled) {
                                fieldset.disabled = false;
                                editBtn.innerHTML = '<i data-lucide="x" class="icon"></i>Cancel';
                                editBtn.className = 'btn-danger';
                                saveBtn.style.display = 'inline-block';
                                lucide.createIcons();
                            } else {
                                fieldset.disabled = true;
                                editBtn.innerHTML = '<i data-lucide="pencil" class="icon"></i>Edit Settings';
                                editBtn.className = 'btn-secondary';
                                lucide.createIcons();
                                saveBtn.style.display = 'none';
                            }
                        }
                    </script>

                    <h3 style="margin-top:24px; font-size:16px;"><i data-lucide="filter" class="icon icon-sm"></i>Sync Filters</h3>
                    <div class="settings-section">
                        <div class="checkbox-wrapper">
                            <input type="checkbox" name="auto_sync" value="1" ${currentAutoSync ? 'checked' : ''} />
                            <label style="margin-bottom:0;">Automatically sync all orders</label>
                        </div>
                        <p class="helper-text">
                            If disabled, only orders with the specified Tag below will be synced.
                        </p>
                        
                        <label for="sync_tag" style="margin-top:16px;">Required Tag (Optional):</label>
                        <input type="text" id="sync_tag" name="sync_tag" placeholder="e.g., send_pathxpress" value="${currentSyncTag}" />
                        <p class="helper-text" style="margin-left:0;">If you enter a tag (e.g., "send_pathxpress"), ONLY orders with that tag in Shopify will be synced.</p>
                    </div>

                    <h3 style="margin-top:24px; font-size:16px;"><i data-lucide="truck" class="icon icon-sm"></i>Default Shipping Service</h3>
                    <p style="font-size:13px; margin-bottom:12px;">Select the default PathXpress service type for all orders from this store.</p>
                    
                    <div class="settings-section">
                        <select name="default_service_type" id="default_service_type">
                            <option value="DOM" ${currentServiceType === 'DOM' ? 'selected' : ''}>DOM - Domestic Standard (1-2 days)</option>
                            <option value="SAMEDAY" ${currentServiceType === 'SAMEDAY' ? 'selected' : ''}>SAMEDAY - Same Day Express</option>
                            <option value="NEXTDAY" ${currentServiceType === 'NEXTDAY' ? 'selected' : ''}>NEXTDAY - Next Day Delivery</option>
                        </select>
                    </div>
                    
                    <h3 style="margin-top:24px; font-size:16px;"><i data-lucide="gift" class="icon icon-sm"></i>Free Shipping</h3>
                    <p style="font-size:13px; margin-bottom:12px;">Set minimum order amounts for free shipping. Leave empty to disable.</p>
                    
                    <div class="settings-section grid-2">
                        <div>
                            <label for="free_shipping_dom"><i data-lucide="package" class="icon icon-sm"></i>Standard (DOM):</label>
                            <input type="number" step="0.01" min="0" id="free_shipping_dom" name="free_shipping_dom" 
                                   placeholder="e.g., 200" value="${freeShippingDOM}" />
                            <p class="helper-text" style="margin-left:0;">1-2 day delivery</p>
                        </div>
                        <div>
                            <label for="free_shipping_express"><i data-lucide="zap" class="icon icon-sm"></i>Express (Same Day):</label>
                            <input type="number" step="0.01" min="0" id="free_shipping_express" name="free_shipping_express" 
                                   placeholder="e.g., 500" value="${freeShippingExpress}" />
                            <p class="helper-text" style="margin-left:0;">Same day delivery</p>
                        </div>
                    </div>
                    
                    </fieldset>

                    <button type="submit" id="saveBtn" style="${currentClientId ? 'display:none;' : ''}">Save Settings</button>
                </form>
              </div>

              <div class="card">
                <h2><i data-lucide="package" class="icon"></i>My PathXpress Shipments</h2>
                <p style="margin-bottom:16px;">Last 20 processed shipments.</p>
                <table>
                    <thead>
                        <tr>
                            <th>Order #</th>
                            <th>Waybill</th>
                            <th>Status</th>
                            <th>Date</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${shipmentsRows}
                    </tbody>
                </table>
              </div>
            `
            : `
              <div class="card" style="text-align:center; padding:40px;">
                <h2 style="justify-content:center;"><i data-lucide="link" class="icon"></i>Connect Your Store</h2>
                <p style="margin-bottom:24px;">To start using PathXpress shipping, connect your Shopify store.</p>
                <a href="/auth?shop=${shop}" target="_top" style="display:inline-flex; align-items:center; gap:8px; background:linear-gradient(135deg, var(--blue-electric), #1e5ad4); color:white; padding:14px 28px; text-decoration:none; border-radius:10px; font-weight:600; box-shadow:0 4px 15px rgba(45, 108, 246, 0.3); transition:all 0.3s ease;"><i data-lucide="rocket" style="width:18px;height:18px;"></i>Connect now</a>
              </div>
            `
        }
        
        <!-- App Bridge for Shopify embedded apps -->
        <script src="https://cdn.shopify.com/shopifycloud/app-bridge.js"></script>
        <script>
            // Initialize App Bridge (deferred to avoid blocking page load)
            (function() {
                try {
                    var AppBridge = window['app-bridge'];
                    if (AppBridge && AppBridge.default) {
                        var host = new URLSearchParams(location.search).get('host');
                        if (host) {
                            window.shopifyApp = AppBridge.default({
                                apiKey: '${process.env.SHOPIFY_API_KEY}',
                                host: host,
                            });
                            console.log('✅ App Bridge initialized');
                        }
                    }
                } catch (e) {
                    console.warn('App Bridge init skipped:', e.message);
                }
            })();
        </script>
        <script>
            // Initialize Lucide Icons
            document.addEventListener('DOMContentLoaded', function() {
                if (typeof lucide !== 'undefined') {
                    lucide.createIcons();
                }
            });
        </script>
      </body >
    </html >
                    `);
});

// ======================
// 4.0.1) API: Validate Client ID
// ======================
app.get("/api/validate-client/:id", async (req, res) => {
    const clientId = req.params.id;

    try {
        // Query the clientAccounts table from PathXpress portal database
        const [rows] = await db.execute(
            "SELECT id, companyName, contactName, billingEmail FROM clientAccounts WHERE id = ?",
            [clientId]
        );

        if (rows.length > 0) {
            res.json({
                found: true,
                companyName: rows[0].companyName || 'Unknown Company',
                contactName: rows[0].contactName || null,
                email: rows[0].billingEmail || null
            });
        } else {
            res.json({ found: false });
        }
    } catch (err) {
        console.error("Error validating client:", err);
        // If table doesn't exist or other error, return not found
        res.json({ found: false, error: 'Could not validate' });
    }
});

// ======================
// 4.1) GUARDAR CONFIGURACIÓN
// ======================
app.post("/app/save-settings", express.urlencoded({ extended: true }), async (req, res) => {
    const { shop, clientId, default_service_type, auto_sync, sync_tag, free_shipping_dom, free_shipping_express } = req.body;

    if (!shop || !clientId) {
        return res.send("Error: Missing data. Please provide a Client ID.");
    }

    const isAutoSync = auto_sync === "1" ? 1 : 0;
    const serviceType = default_service_type || "DOM";
    const freeShippingDOMValue = free_shipping_dom && parseFloat(free_shipping_dom) > 0
        ? parseFloat(free_shipping_dom)
        : null;
    const freeShippingExpressValue = free_shipping_express && parseFloat(free_shipping_express) > 0
        ? parseFloat(free_shipping_express)
        : null;

    try {
        // Use INSERT ... ON DUPLICATE KEY UPDATE to support both new and existing shops
        await db.execute(
            `INSERT INTO shopify_shops (shop_domain, pathxpress_client_id, default_service_type, auto_sync, sync_tag, free_shipping_threshold_dom, free_shipping_threshold_express)
             VALUES (?, ?, ?, ?, ?, ?, ?)
             ON DUPLICATE KEY UPDATE
                pathxpress_client_id = VALUES(pathxpress_client_id),
                default_service_type = VALUES(default_service_type),
                auto_sync = VALUES(auto_sync),
                sync_tag = VALUES(sync_tag),
                free_shipping_threshold_dom = VALUES(free_shipping_threshold_dom),
                free_shipping_threshold_express = VALUES(free_shipping_threshold_express),
                updated_at = CURRENT_TIMESTAMP`,
            [shop, clientId, serviceType, isAutoSync, sync_tag || null, freeShippingDOMValue, freeShippingExpressValue]
        );
        console.log(`⚙️ Settings saved for ${shop}: ClientID = ${clientId}, Service = ${serviceType}, AutoSync = ${isAutoSync}, FreeDOM = ${freeShippingDOMValue}, FreeExpress = ${freeShippingExpressValue}`);
        res.redirect(`/app?shop=${shop}`);
    } catch (err) {
        console.error("Error saving settings:", err);
        res.send("Error saving settings. Please try again.");
    }
});

// ======================
// 4.2) CARRIER SERVICE (Tarifas en Checkout)
// ======================
// ======================
// 4.2) CARRIER SERVICE (Tarifas en Checkout)
// ======================
app.post("/api/shipping-rates", async (req, res) => {
    console.log("💰 Rate request received from Shopify");
    console.log("📋 Full request body:", JSON.stringify(req.body, null, 2));

    try {
        const { rate } = req.body;

        // 1. Intentar obtener shop del header (método más confiable)
        let shop = req.headers['x-shopify-shop-domain'];

        // 2. Fallback: Intentar obtener del callback_url
        if (!shop && rate?.callback_url) {
            const shopMatch = rate.callback_url.match(/https?:\/\/([^\/]+)/);
            if (shopMatch) shop = shopMatch[1];
        }

        console.log(`Store detected: ${shop}`);

        if (!shop) {
            console.warn("⚠️ Could not detect shop domain, using default rates");
            return res.json(getDefaultRates(rate));
        }

        // 3. Obtener configuración de la tienda
        const shopData = await getShopFromDB(shop);
        if (!shopData || !shopData.pathxpress_client_id) {
            console.warn(`⚠️ Shop ${shop} without clientId configured, using default rates`);
            return res.json(getDefaultRates(rate));
        }

        const clientId = shopData.pathxpress_client_id;

        // 4. Obtener cliente con todas sus tarifas
        const [clientRows] = await db.execute(
            `SELECT manualRateTierId, customDomBaseRate, customDomPerKg, customSddBaseRate, customSddPerKg 
             FROM clientAccounts WHERE id = ?`,
            [clientId]
        );

        if (clientRows.length === 0) {
            console.warn(`⚠️ Client ${clientId} not found, using default rates`);
            return res.json(getDefaultRates(rate));
        }

        const client = clientRows[0];

        // 5. Calcular peso total
        const items = rate.items || [];
        const totalWeightGrams = items.reduce((sum, item) => sum + (item.grams || 0) * (item.quantity || 1), 0);
        const totalWeightKg = Math.ceil(totalWeightGrams / 1000) || 1; // Redondear hacia arriba, mínimo 1kg

        console.log(`📦 Calculating rates for client ${clientId}, weight: ${totalWeightKg}kg`);

        let domPrice, sddPrice;

        // 6. PRIORIDAD: Usar tarifas personalizadas del cliente si las tiene
        if (client.customDomBaseRate && client.customDomPerKg) {
            const baseRate = parseFloat(client.customDomBaseRate);
            const perKgRate = parseFloat(client.customDomPerKg);
            // Fórmula: baseRate cubre hasta 5kg, luego +perKgRate por cada kg adicional
            domPrice = baseRate + (Math.max(0, totalWeightKg - 5) * perKgRate);
            console.log(`💰 DOM using custom rates: ${baseRate} + (${Math.max(0, totalWeightKg - 5)} * ${perKgRate}) = ${domPrice}`);
        } else {
            // Fallback a rate tiers si no tiene tarifas personalizadas
            domPrice = await calculateFromTiers(db, client.manualRateTierId, clientId, 'DOM', totalWeightKg);
        }

        if (client.customSddBaseRate && client.customSddPerKg) {
            const baseRate = parseFloat(client.customSddBaseRate);
            const perKgRate = parseFloat(client.customSddPerKg);
            sddPrice = baseRate + (Math.max(0, totalWeightKg - 5) * perKgRate);
            console.log(`💰 SDD using custom rates: ${baseRate} + (${Math.max(0, totalWeightKg - 5)} * ${perKgRate}) = ${sddPrice}`);
        } else {
            // Fallback a rate tiers
            sddPrice = await calculateFromTiers(db, client.manualRateTierId, clientId, 'SDD', totalWeightKg);
        }

        // Usar defaults si no se pudieron calcular
        if (!domPrice) domPrice = 15 + (Math.max(0, totalWeightKg - 5) * 2);
        if (!sddPrice) sddPrice = 25 + (Math.max(0, totalWeightKg - 5) * 3);

        console.log(`💵 Base rates - DOM: ${domPrice} AED, SDD: ${sddPrice} AED`);

        // 7. Verificar FREE SHIPPING (umbrales separados para DOM y Express)
        const freeShippingDOMRaw = shopData.free_shipping_threshold_dom;
        const freeShippingExpressRaw = shopData.free_shipping_threshold_express;
        const freeShippingDOM = freeShippingDOMRaw ? parseFloat(freeShippingDOMRaw) : 0;
        const freeShippingExpress = freeShippingExpressRaw ? parseFloat(freeShippingExpressRaw) : 0;

        let isDOMFree = false;
        let isExpressFree = false;

        console.log(`🔧 Free shipping thresholds - DOM: ${freeShippingDOM}, Express: ${freeShippingExpress}`);

        // Calcular precio total de los productos
        const totalItemsPrice = items.reduce((sum, item) => {
            const itemPrice = parseInt(item.price || 0) / 100; // Convertir de centavos a AED
            return sum + (itemPrice * (item.quantity || 1));
        }, 0);

        console.log(`🛒 Order total: ${totalItemsPrice} AED`);

        // Verificar umbral DOM
        if (freeShippingDOM > 0 && totalItemsPrice >= freeShippingDOM) {
            isDOMFree = true;
            domPrice = 0;
            console.log(`🎁 FREE DOM shipping! ${totalItemsPrice} AED >= ${freeShippingDOM} AED`);
        }

        // Verificar umbral Express
        if (freeShippingExpress > 0 && totalItemsPrice >= freeShippingExpress) {
            isExpressFree = true;
            sddPrice = 0;
            console.log(`🎁 FREE EXPRESS shipping! ${totalItemsPrice} AED >= ${freeShippingExpress} AED`);
        }

        console.log(`💵 Final rates - DOM: ${domPrice} AED${isDOMFree ? ' (FREE!)' : ''}, SDD: ${sddPrice} AED${isExpressFree ? ' (FREE!)' : ''}`);

        // 8. Respuesta formato Shopify
        const response = {
            rates: [
                {
                    service_name: isDOMFree ? "PathXpress Standard (FREE!)" : "PathXpress Standard",
                    service_code: "DOM",
                    total_price: Math.round(domPrice * 100).toString(), // En centavos
                    currency: "AED",
                    min_delivery_date: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
                    max_delivery_date: new Date(Date.now() + 48 * 60 * 60 * 1000).toISOString()
                },
                {
                    service_name: isExpressFree ? "PathXpress Same Day (FREE!)" : "PathXpress Same Day",
                    service_code: "SAMEDAY",
                    total_price: Math.round(sddPrice * 100).toString(), // En centavos
                    currency: "AED",
                    min_delivery_date: new Date().toISOString(),
                    max_delivery_date: new Date(Date.now() + 12 * 60 * 60 * 1000).toISOString()
                }
            ]
        };

        res.json(response);
    } catch (error) {
        console.error("⛔ Error calculating rates:", error);
        res.json(getDefaultRates(req.body.rate));
    }
});

// Helper: Calcular precio desde rateTiers (fallback)
async function calculateFromTiers(db, manualTierId, clientId, serviceType, weightKg) {
    try {
        let tierId = manualTierId;

        // Si no tiene tier manual, calcular por volumen
        if (!tierId) {
            const [volumeRows] = await db.execute(`
                SELECT COUNT(*) as shipmentCount 
                FROM orders 
                WHERE clientId = ? 
                AND createdAt >= DATE_SUB(NOW(), INTERVAL 1 MONTH)
            `, [clientId]);

            const monthlyVolume = volumeRows[0]?.shipmentCount || 0;

            const [tierRows] = await db.execute(`
                SELECT id FROM rateTiers 
                WHERE serviceType = ? 
                AND minVolume <= ? 
                AND (maxVolume IS NULL OR maxVolume >= ?)
                AND isActive = 1
                ORDER BY minVolume DESC 
                LIMIT 1
            `, [serviceType, monthlyVolume, monthlyVolume]);

            if (tierRows.length > 0) {
                tierId = tierRows[0].id;
            }
        }

        if (!tierId) return null;

        const [tierData] = await db.execute(
            "SELECT baseRate, maxWeight, additionalKgRate FROM rateTiers WHERE id = ? AND isActive = 1",
            [tierId]
        );

        if (tierData.length === 0) return null;

        const tier = tierData[0];
        const baseRate = parseFloat(tier.baseRate);
        const maxWeight = tier.maxWeight || 5;
        const additionalKgRate = parseFloat(tier.additionalKgRate);

        if (weightKg <= maxWeight) {
            return baseRate;
        } else {
            return baseRate + ((weightKg - maxWeight) * additionalKgRate);
        }
    } catch (err) {
        console.error("Error calculating from tiers:", err);
        return null;
    }
}

// Helper: Calcular precio según tier
function calculateTierPrice(tier, weightKg) {
    const baseRate = parseFloat(tier.baseRate);
    const maxWeight = tier.maxWeight || 5; // Default 5kg
    const additionalKgRate = parseFloat(tier.additionalKgRate);

    if (weightKg <= maxWeight) {
        return baseRate;
    } else {
        const extraKg = weightKg - maxWeight;
        return baseRate + (extraKg * additionalKgRate);
    }
}

// Helper: Tarifas por defecto (fallback)
function getDefaultRates(rate) {
    const items = rate?.items || [];
    const totalWeightGrams = items.reduce((sum, item) => sum + (item.grams || 0) * (item.quantity || 1), 0);
    const totalWeightKg = Math.ceil(totalWeightGrams / 1000) || 1;

    const basePrice = 15;
    let finalPrice = basePrice;
    if (totalWeightKg > 5) {
        finalPrice += (totalWeightKg - 5) * 2;
    }

    return {
        rates: [
            {
                service_name: "PathXpress Standard",
                service_code: "DOM",
                total_price: (finalPrice * 100).toString(),
                currency: "AED",
                min_delivery_date: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
                max_delivery_date: new Date(Date.now() + 48 * 60 * 60 * 1000).toISOString()
            },
            {
                service_name: "PathXpress Same Day",
                service_code: "SAMEDAY",
                total_price: ((finalPrice + 10) * 100).toString(),
                currency: "AED",
                min_delivery_date: new Date().toISOString(),
                max_delivery_date: new Date(Date.now() + 12 * 60 * 60 * 1000).toISOString()
            }
        ]
    };
}

// ======================
// 5) /auth (inicio OAuth)
// ======================
app.get("/auth", (req, res) => {
    const shop = req.query.shop;
    if (!shop) return res.status(400).send("Missing shop parameter.");

    const scopes = process.env.SCOPES;
    const redirectUri = `${process.env.APP_URL}/auth/callback`;
    const clientId = process.env.SHOPIFY_API_KEY;

    console.log("🔐 Starting OAuth...");
    console.log("👉 Generated Redirect URI:", redirectUri);

    const installUrl =
        `https://${shop}/admin/oauth/authorize?` +
        querystring.stringify({
            client_id: clientId,
            scope: scopes,
            redirect_uri: redirectUri,
        });

    console.log("🔗 Installation URL:", installUrl);

    res.redirect(installUrl);
});

// ======================
// 6) /auth/callback
// ======================
app.get("/auth/callback", async (req, res) => {
    const { shop, code, hmac } = req.query;
    if (!shop || !code || !hmac)
        return res.status(400).send("Incomplete data");

    const map = { ...req.query };
    delete map["hmac"];
    const message = querystring.stringify(map);

    const generatedHash = crypto
        .createHmac("sha256", process.env.SHOPIFY_API_SECRET)
        .update(message)
        .digest("hex");

    if (generatedHash !== hmac) {
        return res.status(400).send("Invalid HMAC");
    }

    const tokenResponse = await fetch(
        `https://${shop}/admin/oauth/access_token`,
        {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                client_id: process.env.SHOPIFY_API_KEY,
                client_secret: process.env.SHOPIFY_API_SECRET,
                code: code,
            }),
        }
    );

    const tokenData = await tokenResponse.json();
    const accessToken = tokenData.access_token;

    console.log("🔥 SHOP INSTALLED:");
    console.log("Shop:", shop);
    console.log("Access Token:", accessToken);

    shopsTokens[shop] = accessToken;
    console.log("Tokens saved in memory:", shopsTokens);

    // Registrar webhook
    await registerOrderWebhook(shop, accessToken);

    // Registrar Carrier Service (Tarifas en checkout)
    await registerCarrierService(shop, accessToken);

    // --- NUEVO: Obtener datos de la tienda y guardar en DB ---
    try {
        const shopRes = await fetch(`https://${shop}/admin/api/2024-07/shop.json`, {
            headers: {
                "X-Shopify-Access-Token": accessToken
            }
        });
        const shopJson = await shopRes.json();
        if (shopJson.shop) {
            console.log("🏪 Shop data obtained:", shopJson.shop.name);
            await saveShopToDB(shop, accessToken, shopJson.shop);
        }
    } catch (error) {
        console.error("⚠️ Error getting shop data:", error);
    }

    return res.send(
        "Installation completed. You can now close this window."
    );
});

// ======================
// 7) TEST: VER ÓRDENES
// ======================
app.get("/shopify/orders-test", async (req, res) => {
    const shop =
        req.query.shop || req.headers["x-shopify-shop-domain"] || "";

    if (!shop) {
        return res.status(400).send("Missing shop parameter.");
    }

    const accessToken = shopsTokens[shop];
    if (!accessToken) {
        return res
            .status(401)
            .send("This shop is not yet connected to PATHXPRESS.");
    }

    try {
        const apiVersion = "2024-07";
        const url = `https://${shop}/admin/api/${apiVersion}/orders.json?limit=5&status=any`;

        console.log("👉 Calling Shopify:", url);

        const response = await fetch(url, {
            method: "GET",
            headers: {
                "X-Shopify-Access-Token": accessToken,
                "Content-Type": "application/json",
            },
        });

        const text = await response.text();
        console.log("🔎 Shopify Response:", response.status, text);

        let data;
        try {
            data = JSON.parse(text);
        } catch (e) {
            console.error("Could not parse JSON:", e);
            return res
                .status(500)
                .send("Error parsing Shopify response. Check console.");
        }

        if (!response.ok) {
            return res
                .status(response.status)
                .send(
                    `<pre>Shopify Error (${response.status}):\n${text}</pre>`
                );
        }

        const orders = data.orders || [];

        let html = `
      <html>
        <head><meta charset="utf-8"><title>Shopify Orders</title></head>
        <body style="font-family: Arial; padding: 20px;">
          <h1>Latest orders from ${shop}</h1>
    `;

        if (orders.length === 0) {
            html += "<p>No orders yet.</p>";
        } else {
            html += "<ul>";
            for (const order of orders) {
                html += `<li>#${order.name} – total: ${order.total_price} ${order.currency}</li>`;
            }
            html += "</ul>";
        }

        html += `
          <p><a href="/app?shop=${shop}">Back to PATHXPRESS Portal</a></p>
        </body>
      </html>
    `;

        res.send(html);
    } catch (err) {
        console.error("Error reading Shopify orders:", err);
        res
            .status(500)
            .send("Error reading Shopify orders (check console).");
    }
});



// ======================
// 8) REGISTRO DEL WEBHOOK
// ======================
async function registerOrderWebhook(shop, accessToken) {
    const apiVersion = "2024-07";
    const webhookUrl = `${process.env.APP_URL}/webhooks/shopify/orders`;

    console.log("📡 Registering webhook for shop:", shop);
    console.log("📡 Webhook URL:", webhookUrl);

    const response = await fetch(
        `https://${shop}/admin/api/${apiVersion}/webhooks.json`,
        {
            method: "POST",
            headers: {
                "X-Shopify-Access-Token": accessToken,
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                webhook: {
                    topic: "orders/create",
                    address: webhookUrl,
                    format: "json",
                },
            }),
        }
    );

    const body = await response.text();
    if (response.status === 422 && body.includes("taken")) {
        console.log("🔔 Order Webhook already registered.");
    } else {
        console.log("🔔 Webhook Registration:", response.status, body);
    }
}

// ======================
// 8.1) REGISTRO CARRIER SERVICE
// ======================
async function registerCarrierService(shop, accessToken) {
    const apiVersion = "2024-07";
    const callbackUrl = `${process.env.APP_URL}/api/shipping-rates`;

    console.log("🚚 Registering CarrierService in:", shop);

    try {
        // 1. Verificar si ya existe
        const getRes = await fetch(`https://${shop}/admin/api/${apiVersion}/carrier_services.json`, {
            headers: { "X-Shopify-Access-Token": accessToken }
        });
        const getData = await getRes.json();
        const existing = (getData.carrier_services || []).find(cs => cs.name === "PathXpress Shipping");

        if (existing) {
            console.log("✅ CarrierService already exists. ID:", existing.id);
            // Opcional: Actualizar URL si cambió
            return;
        }

        // 2. Crear si no existe
        const response = await fetch(`https://${shop}/admin/api/${apiVersion}/carrier_services.json`, {
            method: "POST",
            headers: {
                "X-Shopify-Access-Token": accessToken,
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                carrier_service: {
                    name: "PathXpress Shipping",
                    callback_url: callbackUrl,
                    service_discovery: true // Permite a Shopify preguntar tarifas
                }
            }),
        });

        const json = await response.json();
        if (response.ok) {
            console.log("✅ CarrierService registered successfully:", json.carrier_service.id);
        } else {
            console.error("⚠️ Error registering CarrierService:", JSON.stringify(json));
        }
    } catch (err) {
        console.error("⛔ Exception registering CarrierService:", err);
    }
}

// ======================
// 9) ARRANCAR SERVIDOR
// ======================
app.listen(PORT, () => {
    console.log(
        `PATHXPRESS Shopify Server listening on http://localhost:${PORT}`
    );

    // Iniciar Cron/Intervalo de Sincronización (cada 60 segundos)
    setInterval(syncShipmentsToShopify, 60 * 1000);

    // Iniciar Cron de Reintentos (cada 5 minutos)
    setInterval(processRetryQueue, 5 * 60 * 1000);

    console.log("🔄 Automatic synchronization started (every 60s).");
    console.log("🛡️ Retry system started (every 5m).");
});

// ======================
// 11) SISTEMA DE REINTENTOS (Error Handling)
// ======================
async function processRetryQueue() {
    console.log("🛡️ Checking retry queue...");
    try {
        // Buscar items pendientes con menos de 5 intentos
        const [rows] = await db.execute(`
            SELECT * FROM webhook_retries 
            WHERE status = 'PENDING' AND retry_count < 5
            LIMIT 5
        `);

        if (rows.length === 0) return;

        console.log(`🛡️ Processing ${rows.length} retries...`);

        for (const row of rows) {
            const { id, shop_domain, payload, retry_count } = row;

            try {
                // Parsear payload si viene como string
                let order = payload;
                if (typeof order === 'string') order = JSON.parse(order);

                console.log(`🔄 Retrying order ${order.name} (Attempt ${retry_count + 1})...`);

                // 1. Obtener info tienda
                const shopData = await getShopFromDB(shop_domain);

                // 2. Procesar
                const shipment = orderToShipment(order, shop_domain, shopData);
                await saveShipmentToMySQL(shipment);
                await saveShipmentToOrdersTable(shipment);

                // 3. Marcar como procesado
                await db.execute("UPDATE webhook_retries SET status = 'PROCESSED', updated_at = NOW() WHERE id = ?", [id]);
                console.log(`✅ Successful retry for ID ${id}`);

            } catch (err) {
                console.error(`⛔ Retry failed ID ${id}:`, err.message);
                // Incrementar contador
                await db.execute(`
                    UPDATE webhook_retries 
                    SET retry_count = retry_count + 1, 
                        error_message = ?,
                        status = IF(retry_count >= 5, 'FAILED', 'PENDING')
                    WHERE id = ?
                `, [err.message, id]);
            }
        }
    } catch (err) {
        console.error("⛔ Error in retry cycle:", err);
    }
}

// ======================
// 10) LOGICA DE SINCRONIZACIÓN (Two-Way Sync)
// ======================
async function syncShipmentsToShopify() {
    console.log("🔄 Running status synchronization...");
    try {
        // 1. Buscar envíos que:
        //    - Estén en shopify_shipments (tenemos shop_domain y order_id)
        //    - NO tengan shopify_fulfillment_id (no sincronizados aún)
        //    - Su estado en la tabla `orders` sea 'PICKED_UP', 'IN_TRANSIT', 'OUT_FOR_DELIVERY' o 'DELIVERED'
        //      (Asumimos que PENDING_PICKUP no se sincroniza aún)

        // Hacemos JOIN con `orders` usando orderNumber y shipperName (shop_domain)
        const [rows] = await db.execute(`
            SELECT 
                s.id AS shipment_id,
                s.shop_domain,
                s.shop_order_id,
                s.shop_order_name,
                o.waybillNumber,
                o.status AS current_status
            FROM shopify_shipments s
            JOIN orders o ON (o.orderNumber = s.shop_order_name AND o.shipperName = s.shop_domain)
            WHERE s.shopify_fulfillment_id IS NULL
              AND o.status IN ('PICKED_UP', 'IN_TRANSIT', 'OUT_FOR_DELIVERY', 'DELIVERED')
            LIMIT 10
        `);

        if (rows.length === 0) return;

        console.log(`🔄 Found ${rows.length} shipments to sync with Shopify.`);

        for (const row of rows) {
            await fulfillShopifyOrder(row);
        }

    } catch (err) {
        console.error("⛔ Error in synchronization cycle:", err);
    }
}

async function fulfillShopifyOrder(row) {
    const { shipment_id, shop_domain, shop_order_id, waybillNumber } = row;

    try {
        // 1. Obtener Token de la tienda
        const shopData = await getShopFromDB(shop_domain);
        if (!shopData || !shopData.access_token) {
            console.error(`⚠️ No token for ${shop_domain}, skipping.`);
            return;
        }
        const accessToken = shopData.access_token;

        // 2. Obtener Location ID (necesario para fulfillment)
        //    Pedimos las locations y usamos la primera (normalmente el almacén principal)
        const locRes = await fetch(`https://${shop_domain}/admin/api/2024-07/locations.json`, {
            headers: { "X-Shopify-Access-Token": accessToken }
        });
        const locJson = await locRes.json();
        const locationId = locJson.locations?.[0]?.id;

        if (!locationId) {
            console.error(`⚠️ Location ID not found for ${shop_domain}`);
            return;
        }

        // 3. Crear Fulfillment en Shopify
        //    Incluimos tracking info
        const payload = {
            fulfillment: {
                location_id: locationId,
                tracking_info: {
                    number: waybillNumber,
                    url: `https://pathxpress.net/tracking?id=${waybillNumber}`,
                    company: "PathXpress"
                },
                // line_items_by_fulfillment_order: ... (Si es API nueva 2024, a veces pide fulfillment_order_id)
                // Para simplificar usamos el endpoint legacy de orders/{id}/fulfillments si aún funciona,
                // o el nuevo flujo. La API 2024-07 prefiere fulfillment_orders.
                // Vamos a intentar el método "Fulfillment on Order" legacy que suele redirigir, 
                // o mejor: Buscamos las fulfillment_orders abiertas y cerramos la primera.
            }
        };

        // NOTA: Desde 2023, Shopify deprecó POST /orders/{id}/fulfillments.
        // Hay que usar POST /fulfillments.json con `line_items_by_fulfillment_order`.
        // Paso A: Obtener fulfillment_orders para esta orden
        const foRes = await fetch(`https://${shop_domain}/admin/api/2024-07/orders/${shop_order_id}/fulfillment_orders.json`, {
            headers: { "X-Shopify-Access-Token": accessToken }
        });
        const foJson = await foRes.json();
        const fulfillmentOrders = foJson.fulfillment_orders || [];

        // Filtramos las que estén 'open'
        const openFO = fulfillmentOrders.find(fo => fo.status === 'open' || fo.status === 'in_progress');

        if (!openFO) {
            console.log(`ℹ️ Order ${shop_order_id} has no open fulfillment_orders. Marking as locally synced.`);
            // Actualizamos localmente para no reintentar infinito
            await db.execute("UPDATE shopify_shipments SET shopify_fulfillment_id = 'ALREADY_FULFILLED' WHERE id = ?", [shipment_id]);
            return;
        }

        // Paso B: Crear fulfillment sobre esa fulfillment_order
        const fulfillmentPayload = {
            fulfillment: {
                line_items_by_fulfillment_order: [
                    {
                        fulfillment_order_id: openFO.id
                    }
                ],
                tracking_info: {
                    number: waybillNumber,
                    url: `https://pathxpress.net/tracking?id=${waybillNumber}`,
                    company: "PathXpress"
                }
            }
        };

        const createRes = await fetch(`https://${shop_domain}/admin/api/2024-07/fulfillments.json`, {
            method: "POST",
            headers: {
                "X-Shopify-Access-Token": accessToken,
                "Content-Type": "application/json"
            },
            body: JSON.stringify(fulfillmentPayload)
        });

        const createJson = await createRes.json();

        if (createRes.ok && createJson.fulfillment) {
            const newFulfillmentId = createJson.fulfillment.id;
            console.log(`✅ Fulfillment created in Shopify: ${newFulfillmentId} for order ${shop_order_id}`);

            // 4. Actualizar DB local
            await db.execute("UPDATE shopify_shipments SET shopify_fulfillment_id = ? WHERE id = ?", [newFulfillmentId, shipment_id]);
        } else {
            console.error(`⛔ Error creating fulfillment in Shopify:`, JSON.stringify(createJson));
        }

    } catch (err) {
        console.error(`⛔ Exception syncing order ${shop_order_id}:`, err);
    }
}


function orderToShipment(order, shop, shopData) {
    const shipping = order.shipping_address || order.billing_address || {};
    const customer = order.customer || {};

    // Datos del Shipper (Tienda)
    // Si no hay datos en DB, usamos fallbacks
    const shipperName = shopData?.shop_name || shop;
    const shipperAddress = shopData?.address1 || "";
    const shipperCity = shopData?.city || "Dubai";
    const shipperCountry = shopData?.country || "UAE";
    const shipperPhone = shopData?.phone || "";

    // Peso: Intentamos usar total_weight (en gramos), si no, sumamos items, si no, default 1kg
    let totalWeightKg = order.total_weight ? order.total_weight / 1000 : 0;

    if (!totalWeightKg) {
        // Si Shopify no mandó peso total, intentamos sumar el de los items (si tienen 'grams')
        const itemsWeightGrams = (order.line_items || []).reduce((sum, item) => {
            return sum + (item.grams || 0) * (item.quantity || 1);
        }, 0);
        totalWeightKg = itemsWeightGrams > 0 ? itemsWeightGrams / 1000 : 1; // Default 1kg
    }

    // Dimensiones: Shopify no suele mandar dimensiones por pedido.
    // Usamos defaults o variables de entorno si existieran.
    const length = Number(process.env.DEFAULT_LENGTH) || 15;
    const width = Number(process.env.DEFAULT_WIDTH) || 15;
    const height = Number(process.env.DEFAULT_HEIGHT) || 15;

    // Detección de COD mejorada
    // 1. Verificar si el método de pago incluye "Cash on Delivery" (o similar)
    const paymentGateways = order.payment_gateway_names || [];
    const isCodGateway = paymentGateways.some(pg =>
        /cash|cod|contrareembolso|contra entrega/i.test(pg)
    );

    // 2. Verificar estado financiero (pending/authorized suele ser COD, paid es tarjeta)
    const isFinancialPending =
        order.financial_status === "pending" ||
        order.financial_status === "authorized" ||
        order.financial_status === "partially_paid";

    // Regla final: Es COD si el gateway lo dice O si está pendiente de pago
    // (A veces 'manual' también es COD)
    const isCOD = isCodGateway || (isFinancialPending && paymentGateways.includes("manual"));

    const codAmount = isCOD ? Number(order.total_price) || 0 : 0;

    // Mapeo a clientId del portal
    // YA NO USAMOS MAPPING HARDCODED. Usamos lo que venga en shopData (DB)
    // Si no está configurado, fallback a 1 (o podrías lanzar error/log)
    const clientId = shopData?.pathxpress_client_id || 1;

    if (!shopData?.pathxpress_client_id) {
        console.warn(`⚠️ Shop ${shop} does NOT have pathxpress_client_id configured. Using default: 1`);
    }

    // Determinar Service Type - Usar el tipo de servicio por defecto configurado
    const serviceType = shopData?.default_service_type || "DOM";

    return {
        // info de integración
        source: "SHOPIFY",
        shopDomain: shop,
        shopOrderId: order.id,
        shopOrderName: order.name,

        clientId,

        // SHIPPER (Datos reales de la tienda)
        shipperName,
        shipperAddress,
        shipperCity,
        shipperCountry,
        shipperPhone,

        // CONSIGNEE / CUSTOMER
        consigneeName: `${shipping.first_name || ""} ${shipping.last_name || ""}`.trim(),
        consigneePhone: shipping.phone || customer.phone || "", // Evitar NULL
        consigneeEmail: customer.email || null,
        addressLine1: shipping.address1 || "",
        city: shipping.city || "",
        emirate: shipping.province || "",
        postalCode: shipping.zip || "",
        country: shipping.country || "UAE",

        // Bultos / peso / dimensiones
        pieces: (order.line_items || []).reduce(
            (sum, item) => sum + (item.quantity || 0),
            0
        ) || 1,
        totalWeightKg,
        length,
        width,
        height,
        volumetricWeight: (length * width * height) / 5000, // puedes ajustar divisor

        // Servicio
        serviceType,

        // Instrucciones
        specialInstructions: order.note || "",

        // COD
        codRequired: codAmount > 0 ? 1 : 0,
        codAmount,
        codCurrency: order.currency || "AED",

        // Fechas / estado
        pickupDate: order.created_at || new Date().toISOString(),
        status: "PENDING_PICKUP",
        createdAt: order.created_at || new Date().toISOString(),
        updatedAt: new Date().toISOString(),
    };
}



async function sendShipmentToPathxpress(shipment) {
    // 1) Construimos el objeto input EXACTO que espera tRPC
    const input = {
        token: process.env.PATHXPRESS_PORTAL_TOKEN,
        shipment: {
            // --- SHIPPER (remitente) ---
            shipperName: shipment.shopDomain || "PATHXPRESS SHOPIFY",
            shipperAddress: shipment.shipperAddress || "",
            shipperCity: shipment.shipperCity || "",
            shipperCountry: shipment.shipperCountry || "UAE",
            shipperPhone: shipment.shipperPhone || "",

            // --- CUSTOMER / CONSIGNEE ---
            customerName: shipment.consigneeName || "",
            customerPhone: shipment.consigneePhone || "",
            address: shipment.addressLine1 || "",
            city: shipment.city || "",
            emirate: shipment.province || "",
            destinationCountry: shipment.country || "UAE",

            // --- PIEZAS / PESO / DIMENSIONES ---
            pieces: shipment.items?.length || 1,
            weight: shipment.totalWeightKg || 1,
            length: shipment.length || 15,
            width: shipment.width || 15,
            height: shipment.height || 15,

            // --- SERVICIO ---
            serviceType: shipment.serviceType || "DOM",

            // --- INSTRUCCIONES ---
            specialInstructions: shipment.specialInstructions || "",

            // --- COD ---
            codRequired: shipment.codAmount > 0 ? 1 : 0,
            codAmount: shipment.codAmount || "",
            codCurrency: shipment.currency || "AED",
        },
    };

    // 2) tRPC batch body: [ { json: { input: { ... } } } ]
    const body = [
        {
            json: {
                input,
            },
        },
    ];

    console.log("📤 Enviando a portal.customer.createShipment INPUT:");
    console.dir(input, { depth: null });

    try {
        const response = await fetch(
            "https://pathxpress.net/api/trpc/portal.customer.createShipment?batch=1",
            {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                },
                body: JSON.stringify(body),
            }
        );

        const text = await response.text();
        console.log(
            "📝 Respuesta portal.customer.createShipment:",
            response.status,
            text
        );
    } catch (err) {
        console.error(
            "⛔ Error enviando shipment a PATHXPRESS Portal:",
            err
        );
    }
}

