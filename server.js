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

        // Verificar que el audience (aud) coincida con nuestro Client ID
        const expectedAud = process.env.SHOPIFY_API_KEY;
        if (verified.aud && verified.aud !== expectedAud) {
            console.error("❌ Session token aud mismatch:", verified.aud, "expected:", expectedAud);
            return null;
        }

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
            dest: verified.dest,
            aud: verified.aud
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
        <!-- Shopify App Bridge - Meta tag MUST be before the script -->
        <meta name="shopify-api-key" content="${process.env.SHOPIFY_API_KEY}" />
        <script src="https://cdn.shopify.com/shopifycloud/app-bridge.js"></script>
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
            
            /* Header Logo Styling */
            .header-logo {
                display: flex;
                align-items: center;
                gap: 16px;
                margin-bottom: 16px;
            }
            .logo-img {
                height: 40px;
                width: auto;
                object-fit: contain;
            }
            .portal-badge {
                display: inline-block;
                padding: 6px 14px;
                background: linear-gradient(135deg, var(--blue-electric), #1e5ad4);
                color: white;
                border-radius: 20px;
                font-size: 12px;
                font-weight: 600;
                text-transform: uppercase;
                letter-spacing: 0.5px;
                box-shadow: 0 2px 10px rgba(45, 108, 246, 0.3);
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
            <div class="header-logo">
                <img src="data:image/png;base64,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" alt="PATHXPRESS" class="logo-img" />
                <span class="portal-badge">Shopify Portal</span>
            </div>
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
                        // Helper to get session token from App Bridge
                        async function getSessionToken() {
                            if (window.shopify && window.shopify.id && window.shopify.id.getSessionToken) {
                                try {
                                    return await window.shopify.id.getSessionToken();
                                } catch (err) {
                                    console.warn('Error fetching session token:', err);
                                }
                            }
                            return null;
                        }
                        
                        // Handle Form Submit with Session Token
                        document.addEventListener('DOMContentLoaded', () => {
                            const form = document.getElementById('settingsForm');
                            if (form) {
                                form.addEventListener('submit', async (e) => {
                                    e.preventDefault();
                                    const btn = document.getElementById('saveBtn');
                                    const originalText = btn.innerHTML;
                                    btn.innerHTML = '<span style="display:inline-flex;align-items:center;gap:6px;"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="animation: spin 1s linear infinite;"><circle cx="12" cy="12" r="10"></circle><path d="M12 6v6l4 2"></path></svg>Saving...</span>';
                                    btn.disabled = true;

                                    try {
                                        const token = await getSessionToken();
                                        const formData = new FormData(form);
                                        const data = Object.fromEntries(formData.entries());
                                        
                                        const headers = {
                                            'Content-Type': 'application/json'
                                        };
                                        if (token) {
                                            // Fix: Use concatenation to avoid server-side interpolation of backticks
                                            headers['Authorization'] = 'Bearer ' + token;
                                        }

                                        const res = await fetch('/app/save-settings', {
                                            method: 'POST',
                                            headers: headers,
                                            body: JSON.stringify(data)
                                        });
                                        
                                        let result;
                                        try {
                                            result = await res.json();
                                        } catch (e) {
                                            result = { success: false, message: 'Server error' };
                                        }
                                        
                                        if (res.ok && result.success) {
                                            // Success - reload to show saved state
                                            window.location.reload(); 
                                        } else {
                                            alert('Error: ' + (result.message || 'Unknown error'));
                                            btn.innerHTML = originalText;
                                            btn.disabled = false;
                                        }
                                    } catch (err) {
                                        console.error(err);
                                        alert('Failed to save settings. Please try again.');
                                        btn.innerHTML = originalText;
                                        btn.disabled = false;
                                    }
                                });
                            }
                        });

                        async function validateClientId(id) {
                            if (!id) return;
                            const feedback = document.getElementById('clientFeedback');
                            feedback.style.display = 'block';
                            feedback.className = 'feedback-box feedback-info';
                            feedback.innerHTML = '<span style="display:inline-flex;align-items:center;gap:6px;"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="animation: spin 1s linear infinite;"><circle cx="12" cy="12" r="10"></circle><path d="M12 6v6l4 2"></path></svg>Verifying...</span>';
                            // Add spin animation if not exists
                            if (!document.getElementById('spinAnimation')) {
                                const style = document.createElement('style');
                                style.id = 'spinAnimation';
                                style.textContent = '@keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }';
                                document.head.appendChild(style);
                            }
                            
                            try {
                                // Get session token from App Bridge
                                const sessionToken = await getSessionToken();
                                
                                // Make request with session token in Authorization header
                                const headers = {};
                                if (sessionToken) {
                                    headers['Authorization'] = 'Bearer ' + sessionToken;
                                }
                                
                                const response = await fetch('/api/validate-client/' + id, {
                                    method: 'GET',
                                    headers: headers
                                });
                                
                                const data = await response.json();
                                
                                if (data.found) {
                                    feedback.className = 'feedback-box feedback-success';
                                    feedback.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#22c55e" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="margin-right:6px;"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg><strong>' + data.companyName + '</strong> (Contact: ' + (data.contactName || 'N/A') + ')';
                                } else {
                                    feedback.className = 'feedback-box feedback-error';
                                    feedback.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#ef4444" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="margin-right:6px;"><circle cx="12" cy="12" r="10"></circle><line x1="15" y1="9" x2="9" y2="15"></line><line x1="9" y1="9" x2="15" y2="15"></line></svg>Client ID not found. Please check and try again.';
                                }
                            } catch (e) {
                                console.error('Validation error:', e);
                                feedback.className = 'feedback-box feedback-warning';
                                feedback.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#f59e0b" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="margin-right:6px;"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>Could not verify. Will save anyway.';
                            }
                        }
                        
                        // Auto-validate if there's a value on load (with delay to let App Bridge initialize)
                        setTimeout(function() {
                            if (document.getElementById('clientId').value) {
                                validateClientId(document.getElementById('clientId').value);
                            }
                        }, 1000);
                        
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
        
        < !--App Bridge initialized in head-- >
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
app.post("/app/save-settings", requireSessionToken, async (req, res) => {
    // 1. Validar autenticación vía Session Token
    const session = req.shopifySession;
    let shop = session ? session.shop : null;

    // Fallback para dev/pruebas (si se envía por body, aunque inseguro)
    if (!shop && req.body.shop) {
        shop = req.body.shop;
    }

    if (!shop) {
        return res.status(401).json({ success: false, message: "Unauthorized: Missing shop or valid session." });
    }

    const { clientId, default_service_type, auto_sync, sync_tag, free_shipping_dom, free_shipping_express } = req.body;

    if (!clientId) {
        return res.status(400).json({ success: false, message: "Error: Missing Client ID." });
    }

    const isAutoSync = auto_sync === "1" || auto_sync === true ? 1 : 0;
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
            `INSERT INTO shopify_shops(shop_domain, pathxpress_client_id, default_service_type, auto_sync, sync_tag, free_shipping_threshold_dom, free_shipping_threshold_express)
             VALUES(?, ?, ?, ?, ?, ?, ?)
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
        console.log(`⚙️ Settings saved for ${shop}: ClientID = ${clientId}, Service = ${serviceType}, AutoSync = ${isAutoSync} `);

        // Return JSON success
        res.json({ success: true, message: "Settings saved successfully" });
    } catch (err) {
        console.error("Error saving settings:", err);
        res.status(500).json({ success: false, message: "Internal server error saving settings." });
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

        console.log(`Store detected: ${shop} `);

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
             FROM clientAccounts WHERE id = ? `,
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

        console.log(`📦 Calculating rates for client ${clientId}, weight: ${totalWeightKg} kg`);

        let domPrice, sddPrice;

        // 6. PRIORIDAD: Usar tarifas personalizadas del cliente si las tiene
        if (client.customDomBaseRate && client.customDomPerKg) {
            const baseRate = parseFloat(client.customDomBaseRate);
            const perKgRate = parseFloat(client.customDomPerKg);
            // Fórmula: baseRate cubre hasta 5kg, luego +perKgRate por cada kg adicional
            domPrice = baseRate + (Math.max(0, totalWeightKg - 5) * perKgRate);
            console.log(`💰 DOM using custom rates: ${baseRate} + (${Math.max(0, totalWeightKg - 5)} * ${perKgRate}) = ${domPrice} `);
        } else {
            // Fallback a rate tiers si no tiene tarifas personalizadas
            domPrice = await calculateFromTiers(db, client.manualRateTierId, clientId, 'DOM', totalWeightKg);
        }

        if (client.customSddBaseRate && client.customSddPerKg) {
            const baseRate = parseFloat(client.customSddBaseRate);
            const perKgRate = parseFloat(client.customSddPerKg);
            sddPrice = baseRate + (Math.max(0, totalWeightKg - 5) * perKgRate);
            console.log(`💰 SDD using custom rates: ${baseRate} + (${Math.max(0, totalWeightKg - 5)} * ${perKgRate}) = ${sddPrice} `);
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

        console.log(`🔧 Free shipping thresholds - DOM: ${freeShippingDOM}, Express: ${freeShippingExpress} `);

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

        console.log(`💵 Final rates - DOM: ${domPrice} AED${isDOMFree ? ' (FREE!)' : ''}, SDD: ${sddPrice} AED${isExpressFree ? ' (FREE!)' : ''} `);

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
        AND(maxVolume IS NULL OR maxVolume >= ?)
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
// HELPER: Calcular Tarifas desde Tiers
// ======================
async function calculateFromTiers_DISABLED(db, tierId, clientId, serviceCode, weightKg) {
    // Default fallback values
    const isSdd = serviceCode === 'SDD' || serviceCode === 'SAMEDAY';
    const defaultBase = isSdd ? 25 : 15;
    const defaultPerKg = isSdd ? 3 : 2;

    if (!tierId) {
        return defaultBase + (Math.max(0, weightKg - 5) * defaultPerKg);
    }

    try {
        // Intentamos leer de rateTiers
        // NOTA: Ajustar nombres de columnas según schema real. 
        // Se asume: sddBasePrice, sddPerKg, domBasePrice, domPerKg
        const [rows] = await db.execute("SELECT * FROM rateTiers WHERE id = ?", [tierId]);

        if (rows.length === 0) {
            console.warn(`⚠️ Rate Tier ${tierId} not found, using defaults.`);
            return defaultBase + (Math.max(0, weightKg - 5) * defaultPerKg);
        }

        const tier = rows[0];

        const base = isSdd
            ? (parseFloat(tier.sddBasePrice || tier.sdd_base_price || 25))
            : (parseFloat(tier.domBasePrice || tier.dom_base_price || 15));

        const perKg = isSdd
            ? (parseFloat(tier.sddPerKg || tier.sdd_per_kg || 3))
            : (parseFloat(tier.domPerKg || tier.dom_per_kg || 2));

        const price = base + (Math.max(0, weightKg - 5) * perKg);
        return price;

    } catch (e) {
        console.error("⛔ Error calculating from tiers:", e);
        return defaultBase + (Math.max(0, weightKg - 5) * defaultPerKg);
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

        // Hacemos JOIN con `shopify_shops` para obtener el clientId, y luego con `orders`
        const [rows] = await db.execute(`
            SELECT 
                s.id AS shipment_id,
                s.shop_domain,
                s.shop_order_id,
                s.shop_order_name,
                o.waybillNumber,
                o.status AS current_status
            FROM shopify_shipments s
            JOIN shopify_shops ss ON ss.shop_domain = s.shop_domain
            JOIN orders o ON (o.orderNumber = s.shop_order_name AND o.clientId = ss.pathxpress_client_id)
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

        // 2. Crear Fulfillment en Shopify
        //    (Ya no necesitamos location_id explícito si usamos fulfillment_orders)

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

// ======================
// KEEP-ALIVE: Prevent Koyeb from sleeping
// ======================
const KEEP_ALIVE_INTERVAL = 4 * 60 * 1000; // 4 minutes (before 5 min timeout)

function keepAlive() {
    const appUrl = process.env.APP_URL;
    if (!appUrl) {
        console.log("⚠️ APP_URL not set, keep-alive disabled");
        return;
    }

    setInterval(async () => {
        try {
            const response = await fetch(appUrl);
            console.log(`🏓 Keep-alive ping: ${response.status}`);
        } catch (err) {
            console.log("⚠️ Keep-alive ping failed:", err.message);
        }
    }, KEEP_ALIVE_INTERVAL);

    console.log(`🔄 Keep-alive enabled: pinging every ${KEEP_ALIVE_INTERVAL / 1000}s`);
}

// ======================
// START SERVER
// ======================
app.listen(PORT, () => {
    console.log(`🚀 PATHXPRESS Shopify App running on port ${PORT}`);
    console.log(`📡 App URL: ${process.env.APP_URL || 'Not configured'}`);

    // Start keep-alive after server is running
    keepAlive();
});
