// ======================
// IMPORTS Y CONFIG
// ======================
import mysql from "mysql2/promise";
import express from "express";
import dotenv from "dotenv";
import crypto from "crypto";
import querystring from "querystring";


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

        console.log("🗄️ Shipment guardado en MySQL, id:", result.insertId);
    } catch (err) {
        console.error("⛔ Error guardando shipment en MySQL:", err);
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

        console.log("🔢 Generado Waybill:", newWaybillNumber);

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
        console.log("📥 Shipment insertado en tabla `orders`, id:", insertedOrderId);

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
                console.log("💰 Registro COD creado para orden:", insertedOrderId);
            } catch (codErr) {
                console.error("⛔ Error creando registro COD:", codErr);
            }
        }
    } catch (err) {
        console.error("⛔ Error guardando en tabla `orders`:", err);
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
        console.log(`💾 Tienda ${shopDomain} guardada/actualizada en DB.`);
    } catch (err) {
        console.error("⛔ Error guardando tienda en DB:", err);
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
        console.error("⛔ Error obteniendo tienda de DB:", err);
        return null;
    }
}

// Tokens en memoria por tienda
const shopsTokens = {}; // { "tienda.myshopify.com": "ACCESS_TOKEN" }

// Mapeo tienda Shopify -> cliente del portal
// YA NO USAMOS HARDCODED MAPPING. SE USA DB (shopify_shops.pathxpress_client_id)


// ======================
// 1) WEBHOOK (PRIMERO, ANTES DE express.json())
// ======================
app.post(
    "/webhooks/shopify/orders",
    express.raw({ type: "application/json" }),
    async (req, res) => {
        const shop = req.headers["x-shopify-shop-domain"];

        try {
            const bodyString = req.body.toString("utf8");
            const order = JSON.parse(bodyString);

            console.log("📦 Nueva ORDER desde Shopify:", order.name);

            // 1. Obtener info de la tienda de la DB para llenar el Shipper
            const shopData = await getShopFromDB(shop);

            // --- IDEMPOTENCIA (Evitar duplicados) ---
            // Verificar si ya procesamos esta orden (por ID de Shopify)
            const [existing] = await db.execute(
                "SELECT id FROM shopify_shipments WHERE shop_domain = ? AND shop_order_id = ?",
                [shop, order.id]
            );

            if (existing.length > 0) {
                console.log(`⚠️ Orden ${order.name} ya existe en DB. Ignorando duplicado.`);
                return res.sendStatus(200);
            }

            // --- FILTRADO DE ÓRDENES ---
            if (shopData) {
                const autoSync = shopData.auto_sync !== 0;
                const requiredTag = shopData.sync_tag;
                const orderTags = (order.tags || "").split(",").map(t => t.trim());

                // Caso A: AutoSync desactivado y NO tiene el tag requerido
                if (!autoSync && requiredTag && !orderTags.includes(requiredTag)) {
                    console.log(`🚫 Orden ${order.name} ignorada: AutoSync OFF y no tiene tag '${requiredTag}'`);
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
                        console.log(`🚫 Orden ${order.name} ignorada: Requiere tag '${requiredTag}'`);
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

            console.log("🚚 Shipment listo para guardar en MySQL:");
            console.dir(shipment, { depth: null });

            // 1) log / auditoría Shopify
            await saveShipmentToMySQL(shipment);

            // 2) insertar en tabla principal orders
            await saveShipmentToOrdersTable(shipment);

        } catch (e) {
            console.log("⚠️ Error procesando orden del webhook:", e);

            // GUARDAR EN COLA DE REINTENTOS
            try {
                const bodyString = req.body.toString("utf8"); // Recuperar body original
                await db.execute(`
                    INSERT INTO webhook_retries (shop_domain, payload, error_message)
                    VALUES (?, ?, ?)
                `, [shop, bodyString, e.message]);
                console.log("🛡️ Orden guardada en cola de reintentos.");
            } catch (dbErr) {
                console.error("⛔ Error CRÍTICO guardando en reintentos:", dbErr);
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
    res.send("PATHXPRESS Shopify App está corriendo ✅");
});
// ======================
// 4) PANTALLA PRINCIPAL /app
// ======================
app.get("/app", async (req, res) => {
    const shop =
        req.query.shop || req.headers["x-shopify-shop-domain"] || "";

    if (!shop) {
        return res.status(400).send("No se pudo detectar la tienda (shop).");
    }

    const isConnected = Boolean(shopsTokens[shop]);

    // Obtener configuración actual de la DB
    let currentClientId = "";
    let currentAutoSync = true;
    let currentSyncTag = "";
    let shipmentsRows = "<tr><td colspan='5'>No hay envíos recientes.</td></tr>";
    let metrics = { todayCount: 0, activeCount: 0, pendingCod: 0 };

    if (isConnected) {
        // 1. Obtener datos de la tienda (Client ID)
        const shopData = await getShopFromDB(shop);
        if (shopData) {
            currentClientId = shopData.pathxpress_client_id;
            currentAutoSync = shopData.auto_sync !== 0; // MySQL boolean is 0/1
            currentSyncTag = shopData.sync_tag || "";
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
                    <tr style="border-bottom:1px solid #eee;">
                        <td style="padding:10px;">${row.shop_order_name}</td>
                        <td style="padding:10px;"><b>${row.waybillNumber || '---'}</b></td>
                        <td style="padding:10px;">
                            <span style="background:#e4e5e7; padding:2px 6px; border-radius:4px; font-size:12px;">
                                ${row.status}
                            </span>
                        </td>
                        <td style="padding:10px; color:#666;">${new Date(row.createdAt).toLocaleDateString()}</td>
                        <td style="padding:10px;">
                            ${row.waybillNumber
                            ? `<button onclick='generateWaybillPDF(${shipmentData})' style="background:none; border:none; cursor:pointer; color:#008060; font-weight:bold; text-decoration:underline;">🖨️ Imprimir Etiqueta</button>`
                            : '<span style="color:#999;">Pendiente</span>'
                        }
                        </td>
                    </tr>
                `}).join("");
            }
        } catch (err) {
            console.error("Error obteniendo envíos para dashboard:", err);
        }
    }

    res.send(`
    <html>
      <head>
        <meta charset="utf-8" />
        <title>PATHXPRESS Portal</title>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js"></script>
        <script src="https://cdn.jsdelivr.net/npm/jsbarcode@3.11.5/dist/JsBarcode.all.min.js"></script>
        <style>
            body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; padding: 25px; color: #333; }
            .card { background: white; border: 1px solid #dfe3e8; border-radius: 4px; padding: 20px; margin-bottom: 20px; box-shadow: 0 0 0 1px rgba(63, 63, 68, 0.05), 0 1px 3px 0 rgba(63, 63, 68, 0.15); }
            h1 { font-size: 24px; margin-bottom: 10px; }
            h2 { font-size: 18px; margin-bottom: 10px; }
            label { display: block; margin-bottom: 5px; font-weight: 600; }
            input[type="text"], input[type="number"] { width: 100%; padding: 10px; margin-bottom: 15px; border: 1px solid #c4cdd5; border-radius: 3px; box-sizing: border-box; }
            button { background: #008060; color: white; border: none; padding: 10px 20px; border-radius: 3px; cursor: pointer; font-weight: bold; }
            button:hover { background: #006e52; }
            .metric-card { flex: 1; background: #f9fafb; padding: 15px; border-radius: 8px; text-align: center; border: 1px solid #e5e7eb; }
            .metric-val { font-size: 24px; font-weight: bold; color: #111827; margin-top: 5px; }
            .metric-label { font-size: 12px; color: #6b7280; text-transform: uppercase; letter-spacing: 0.5px; }
        </style>
        <script>
            function generateWaybillPDF(shipment) {
                const { jsPDF } = window.jspdf;
                const pdf = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' });

                pdf.setFillColor('#1e40af');
                pdf.rect(0, 0, 210, 40, 'F');
                pdf.setTextColor(255, 255, 255);
                pdf.setFontSize(24);
                pdf.setFont('helvetica', 'bold');
                pdf.text('PATHXPRESS', 15, 20);
                pdf.setFontSize(10);
                pdf.setFont('helvetica', 'normal');
                pdf.text('Reliable Delivery Services in the UAE', 15, 28);
                pdf.setFontSize(16);
                pdf.setFont('helvetica', 'bold');
                pdf.text('Waybill: ' + shipment.waybillNumber, 15, 36);

                const canvas = document.createElement('canvas');
                try {
                    JsBarcode(canvas, shipment.waybillNumber, { format: 'CODE128', width: 2, height: 60, displayValue: false });
                    pdf.addImage(canvas.toDataURL('image/png'), 'PNG', 140, 10, 60, 25);
                } catch (e) { console.error(e); }

                pdf.setFillColor('#dc2626');
                pdf.roundedRect(140, 36, 60, 8, 2, 2, 'F');
                pdf.setTextColor(255, 255, 255);
                pdf.setFontSize(10);
                pdf.text(shipment.serviceType === 'SAMEDAY' ? 'EXPRESS' : 'STANDARD', 170, 41, { align: 'center' });

                pdf.setTextColor('#1f2937');
                let yPos = 55;
                pdf.setFillColor('#f3f4f6');
                pdf.rect(10, yPos, 90, 8, 'F');
                pdf.setFontSize(12);
                pdf.setFont('helvetica', 'bold');
                pdf.text('SHIPPER INFORMATION', 15, yPos + 5.5);
                yPos += 12;
                pdf.setFontSize(10);
                pdf.text(shipment.shipperName || '', 15, yPos);
                yPos += 5;
                pdf.setFont('helvetica', 'normal');
                pdf.text(shipment.shipperAddress || '', 15, yPos);
                yPos += 5;
                pdf.text((shipment.shipperCity || '') + ', ' + (shipment.shipperCountry || ''), 15, yPos);
                yPos += 5;
                pdf.text('Phone: ' + (shipment.shipperPhone || ''), 15, yPos);

                yPos = 55;
                pdf.setFillColor('#f3f4f6');
                pdf.rect(110, yPos, 90, 8, 'F');
                pdf.setFontSize(12);
                pdf.setFont('helvetica', 'bold');
                pdf.text('CONSIGNEE INFORMATION', 115, yPos + 5.5);
                yPos += 12;
                pdf.setFontSize(10);
                pdf.text(shipment.customerName || '', 115, yPos);
                yPos += 5;
                pdf.setFont('helvetica', 'normal');
                pdf.text(shipment.address || '', 115, yPos);
                yPos += 5;
                pdf.text((shipment.city || '') + ', ' + (shipment.destinationCountry || ''), 115, yPos);
                yPos += 5;
                pdf.text('Phone: ' + (shipment.customerPhone || ''), 115, yPos);

                if (shipment.codRequired && shipment.codAmount) {
                    yPos = 100;
                    pdf.setFillColor(255, 165, 0);
                    pdf.rect(10, yPos, 190, 15, 'F');
                    pdf.setTextColor(255, 255, 255);
                    pdf.setFontSize(14);
                    pdf.setFont('helvetica', 'bold');
                    pdf.text('⚠ CASH ON DELIVERY (COD)', 15, yPos + 6);
                    pdf.setFontSize(12);
                    pdf.text('COLLECT: ' + shipment.codAmount + ' ' + (shipment.codCurrency || 'AED'), 15, yPos + 12);
                    pdf.setTextColor('#1f2937');
                    yPos += 20;
                } else {
                    yPos = 100;
                }

                pdf.setFillColor('#f3f4f6');
                pdf.rect(10, yPos, 190, 8, 'F');
                pdf.setFontSize(12);
                pdf.setFont('helvetica', 'bold');
                pdf.text('SHIPMENT DETAILS', 15, yPos + 5.5);
                yPos += 15;
                pdf.setFontSize(10);
                pdf.setFont('helvetica', 'bold');
                pdf.text('Pieces:', 15, yPos);
                pdf.setFont('helvetica', 'normal');
                pdf.text((shipment.pieces || 1).toString(), 35, yPos);
                pdf.setFont('helvetica', 'bold');
                pdf.text('Weight:', 75, yPos);
                pdf.setFont('helvetica', 'normal');
                pdf.text((shipment.weight || 0) + ' kg', 95, yPos);
                pdf.setFont('helvetica', 'bold');
                pdf.text('Status:', 135, yPos);
                pdf.setFont('helvetica', 'normal');
                pdf.text((shipment.status || '').replace(/_/g, ' ').toUpperCase(), 155, yPos);

                yPos = 150;
                try {
                    const canvas2 = document.createElement('canvas');
                    JsBarcode(canvas2, shipment.waybillNumber, { format: 'CODE128', width: 3, height: 80, displayValue: true, fontSize: 14 });
                    pdf.addImage(canvas2.toDataURL('image/png'), 'PNG', 40, yPos, 130, 40);
                } catch (e) { console.error(e); }

                pdf.setFontSize(8);
                pdf.setTextColor(128, 128, 128);
                pdf.text('PATHXPRESS FZCO | Dubai, UAE | info@pathxpress.ae', 105, 270, { align: 'center' });
                pdf.save('waybill-' + shipment.waybillNumber + '.pdf');
            }
        </script>
      </head>
      <body>
        <div class="card">
            <h1>PATHXPRESS Portal</h1>
            <p>Tienda conectada: <b>${shop}</b></p>
            ${isConnected ? '<span style="color:green; font-weight:bold;">● Conectado</span>' : '<span style="color:red; font-weight:bold;">● Desconectado</span>'}
        </div>

        ${isConnected
            ? `
              <div class="card">
                <div style="display:flex; gap:20px;">
                    <div class="metric-card">
                        <div class="metric-label">Envíos Hoy</div>
                        <div class="metric-val">${metrics.todayCount || 0}</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-label">Envíos Activos</div>
                        <div class="metric-val">${metrics.activeCount || 0}</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-label">COD Pendiente</div>
                        <div class="metric-val">AED ${(metrics.pendingCod || 0).toLocaleString()}</div>
                    </div>
                </div>
              </div>

              <div class="card">
                <h2>⚙️ Configuración General</h2>
                <form action="/app/save-settings" method="POST">
                    <input type="hidden" name="shop" value="${shop}" />
                    
                    <label for="clientId">PathXpress Client ID:</label>
                    <input type="number" id="clientId" name="clientId" placeholder="Ej: 123" required value="${currentClientId || ''}" />

                    <h3 style="margin-top:20px; font-size:16px;">🔍 Filtros de Sincronización</h3>
                    <div style="margin-bottom:15px; padding:10px; background:#f4f6f8; border-radius:4px;">
                        <label style="display:flex; align-items:center; gap:10px; font-weight:normal;">
                            <input type="checkbox" name="auto_sync" value="1" ${currentAutoSync ? 'checked' : ''} />
                            Sincronizar automáticamente todos los pedidos
                        </label>
                        <p style="font-size:12px; color:#666; margin-left:25px; margin-top:5px;">
                            Si desactivas esto, solo se sincronizarán los pedidos que tengan el Tag especificado abajo.
                        </p>
                        
                        <label for="sync_tag" style="margin-top:10px;">Tag requerido (Opcional):</label>
                        <input type="text" id="sync_tag" name="sync_tag" placeholder="Ej: send_pathxpress" value="${currentSyncTag}" />
                        <p style="font-size:12px; color:#666;">Si escribes un tag (ej: "send_pathxpress"), SOLO se sincronizarán los pedidos que tengan esa etiqueta en Shopify.</p>
                    </div>

                    <h3 style="margin-top:20px; font-size:16px;">🚚 Mapeo de Servicios de Envío</h3>
                    <p style="font-size:13px; color:#666;">Escribe el nombre exacto del método de envío en Shopify y el código de servicio en PathXpress (ej: DOM, SAMEDAY).</p>
                    
                    <div id="mapping-container">
                        ${(() => {
                let mappingHtml = '';
                let mapping = {};
                try {
                    if (shopData && shopData.service_mapping) {
                        mapping = typeof shopData.service_mapping === 'string'
                            ? JSON.parse(shopData.service_mapping)
                            : shopData.service_mapping;
                    }
                } catch (e) { }

                const keys = Object.keys(mapping);
                if (keys.length > 0) {
                    keys.forEach(key => {
                        mappingHtml += `
                                    <div style="display:flex; gap:10px; margin-bottom:10px;">
                                        <input type="text" name="shopify_service[]" value="${key}" placeholder="Shopify: Standard Shipping" style="flex:1; margin-bottom:0;" />
                                        <input type="text" name="pathxpress_service[]" value="${mapping[key]}" placeholder="PathXpress: DOM" style="width:120px; margin-bottom:0;" />
                                    </div>`;
                    });
                }

                // Siempre agregar una fila vacía extra al final para nuevos mapeos
                mappingHtml += `
                                <div style="display:flex; gap:10px; margin-bottom:10px;">
                                    <input type="text" name="shopify_service[]" placeholder="Shopify: Standard Shipping" style="flex:1; margin-bottom:0;" />
                                    <input type="text" name="pathxpress_service[]" placeholder="PathXpress: DOM" style="width:120px; margin-bottom:0;" />
                                </div>`;

                return mappingHtml;
            })()}
                    </div>

                    <button type="submit">Guardar Configuración</button>
                </form>
              </div>

              <div class="card">
                <h2>📦 Mis Envíos PathXpress</h2>
                <p>Últimos 20 envíos procesados.</p>
                <table style="width:100%; border-collapse:collapse; font-size:14px;">
                    <thead>
                        <tr style="background:#f4f6f8; text-align:left;">
                            <th style="padding:10px; border-bottom:1px solid #dfe3e8;">Order #</th>
                            <th style="padding:10px; border-bottom:1px solid #dfe3e8;">Waybill</th>
                            <th style="padding:10px; border-bottom:1px solid #dfe3e8;">Status</th>
                            <th style="padding:10px; border-bottom:1px solid #dfe3e8;">Fecha</th>
                            <th style="padding:10px; border-bottom:1px solid #dfe3e8;">Acciones</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${shipmentsRows}
                    </tbody>
                </table>
              </div>
            `
            : `
              <div class="card">
                <p>Para comenzar, conecta tu tienda a PATHXPRESS.</p>
                <a href="/auth?shop=${shop}" target="_top" style="background:#008060; color:white; padding:12px 20px; text-decoration:none; border-radius:4px; font-weight:bold;">Conectar ahora</a>
              </div>
            `
        }
      </body >
    </html >
                    `);
});

// ======================
// 4.1) GUARDAR CONFIGURACIÓN
// ======================
app.post("/app/save-settings", express.urlencoded({ extended: true }), async (req, res) => {
    const { shop, clientId, shopify_service, pathxpress_service, auto_sync, sync_tag } = req.body;

    if (!shop || !clientId) {
        return res.send("Error: Faltan datos.");
    }

    // Procesar mapeo de servicios
    const serviceMapping = {};
    if (Array.isArray(shopify_service) && Array.isArray(pathxpress_service)) {
        for (let i = 0; i < shopify_service.length; i++) {
            const sName = shopify_service[i].trim();
            const pCode = pathxpress_service[i].trim();
            if (sName && pCode) {
                serviceMapping[sName] = pCode;
            }
        }
    }

    const isAutoSync = auto_sync === "1" ? 1 : 0;

    try {
        await db.execute(
            "UPDATE shopify_shops SET pathxpress_client_id = ?, service_mapping = ?, auto_sync = ?, sync_tag = ? WHERE shop_domain = ?",
            [clientId, JSON.stringify(serviceMapping), isAutoSync, sync_tag || null, shop]
        );
        console.log(`⚙️ Configuración actualizada para ${shop}: ClientID = ${clientId}, AutoSync = ${isAutoSync}, Tag = ${sync_tag} `);
        res.redirect(`/app?shop=${shop}`);
    } catch (err) {
        console.error("Error guardando settings:", err);
        res.send("Error guardando configuración.");
    }
});

// ======================
// 4.2) CARRIER SERVICE (Tarifas en Checkout)
// ======================
// ======================
// 4.2) CARRIER SERVICE (Tarifas en Checkout)
// ======================
app.post("/api/shipping-rates", async (req, res) => {
    console.log("💰 Solicitud de cotización recibida de Shopify");

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
            console.warn("⚠️ No se pudo detectar shop domain, usando tarifas por defecto");
            return res.json(getDefaultRates(rate));
        }

        // 3. Obtener configuración de la tienda
        const shopData = await getShopFromDB(shop);
        if (!shopData || !shopData.pathxpress_client_id) {
            console.warn(`⚠️ Tienda ${shop} sin clientId configurado, usando tarifas por defecto`);
            return res.json(getDefaultRates(rate));
        }

        const clientId = shopData.pathxpress_client_id;

        // 4. Obtener cliente y su tier
        const [clientRows] = await db.execute(
            "SELECT manualRateTierId FROM clientAccounts WHERE id = ?",
            [clientId]
        );

        if (clientRows.length === 0) {
            console.warn(`⚠️ Cliente ${clientId} no encontrado, usando tarifas por defecto`);
            return res.json(getDefaultRates(rate));
        }

        const client = clientRows[0];
        let tierId = client.manualRateTierId;

        // 5. Si no tiene tier manual, calcular por volumen
        if (!tierId) {
            // Contar envíos del último mes
            const [volumeRows] = await db.execute(`
                SELECT COUNT(*) as shipmentCount 
                FROM orders 
                WHERE clientId = ? 
                AND createdAt >= DATE_SUB(NOW(), INTERVAL 1 MONTH)
            `, [clientId]);

            const monthlyVolume = volumeRows[0]?.shipmentCount || 0;

            // Buscar tier automático por volumen para DOM
            const [tierRows] = await db.execute(`
                SELECT id FROM rateTiers 
                WHERE serviceType = 'DOM' 
                AND minVolume <= ? 
                AND (maxVolume IS NULL OR maxVolume >= ?)
                AND isActive = 1
                ORDER BY minVolume DESC 
                LIMIT 1
            `, [monthlyVolume, monthlyVolume]);

            if (tierRows.length > 0) {
                tierId = tierRows[0].id;
                console.log(`📊 Tier automático asignado por volumen ${monthlyVolume}: Tier ${tierId}`);
            }
        } else {
            console.log(`🎯 Usando tier manual: ${tierId}`);
        }

        // 6. Obtener tarifas de los tiers (DOM y SDD)
        // Si no hay tier asignado (ni manual ni auto), usar default
        if (!tierId) {
            console.warn("⚠️ No se pudo determinar ningún tier, usando tarifas por defecto");
            return res.json(getDefaultRates(rate));
        }

        const [domTierRows] = await db.execute(
            "SELECT * FROM rateTiers WHERE id = ? AND serviceType = 'DOM' AND isActive = 1",
            [tierId]
        );

        const [sddTierRows] = await db.execute(
            "SELECT * FROM rateTiers WHERE serviceType = 'SDD' AND isActive = 1 ORDER BY minVolume ASC LIMIT 1"
        );

        if (domTierRows.length === 0) {
            console.warn(`⚠️ No se encontró tier DOM para ${tierId}, usando tarifas por defecto`);
            return res.json(getDefaultRates(rate));
        }

        const domTier = domTierRows[0];
        const sddTier = sddTierRows[0] || domTier; // Fallback a DOM si no hay SDD

        // 7. Calcular peso total
        const items = rate.items || [];
        const totalWeightGrams = items.reduce((sum, item) => sum + (item.grams || 0) * (item.quantity || 1), 0);
        const totalWeightKg = Math.ceil(totalWeightGrams / 1000) || 1; // Redondear hacia arriba, mínimo 1kg

        // 8. Calcular precios según tier
        const domPrice = calculateTierPrice(domTier, totalWeightKg);
        const sddPrice = calculateTierPrice(sddTier, totalWeightKg);

        console.log(`💵 Tarifas calculadas - DOM: ${domPrice} AED, SDD: ${sddPrice} AED (Peso: ${totalWeightKg}kg)`);

        // 9. Respuesta formato Shopify
        // Convertir a centavos (Shopify espera el precio en la unidad menor de la moneda, pero como string)
        // OJO: Shopify espera el precio en la moneda de la tienda. Asumimos que la tienda está en AED o USD.
        // Si la tienda está en USD, habría que convertir. Por ahora enviamos el valor numérico tal cual.

        const response = {
            rates: [
                {
                    service_name: "PathXpress Standard",
                    service_code: "DOM",
                    total_price: (domPrice * 100).toString(), // En centavos
                    currency: "AED",
                    min_delivery_date: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
                    max_delivery_date: new Date(Date.now() + 48 * 60 * 60 * 1000).toISOString()
                },
                {
                    service_name: "PathXpress Same Day",
                    service_code: "SAMEDAY",
                    total_price: (sddPrice * 100).toString(), // En centavos
                    currency: "AED",
                    min_delivery_date: new Date().toISOString(),
                    max_delivery_date: new Date(Date.now() + 12 * 60 * 60 * 1000).toISOString()
                }
            ]
        };

        res.json(response);
    } catch (error) {
        console.error("⛔ Error calculando tarifas:", error);
        res.json(getDefaultRates(req.body.rate));
    }
});

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
    if (!shop) return res.status(400).send("Falta el parámetro shop.");

    const scopes = process.env.SCOPES;
    const redirectUri = `${process.env.APP_URL}/auth/callback`;
    const clientId = process.env.SHOPIFY_API_KEY;

    console.log("🔐 Iniciando OAuth...");
    console.log("👉 Redirect URI generada:", redirectUri);

    const installUrl =
        `https://${shop}/admin/oauth/authorize?` +
        querystring.stringify({
            client_id: clientId,
            scope: scopes,
            redirect_uri: redirectUri,
        });

    console.log("🔗 URL de instalación:", installUrl);

    res.redirect(installUrl);
});

// ======================
// 6) /auth/callback
// ======================
app.get("/auth/callback", async (req, res) => {
    const { shop, code, hmac } = req.query;
    if (!shop || !code || !hmac)
        return res.status(400).send("Datos incompletos");

    const map = { ...req.query };
    delete map["hmac"];
    const message = querystring.stringify(map);

    const generatedHash = crypto
        .createHmac("sha256", process.env.SHOPIFY_API_SECRET)
        .update(message)
        .digest("hex");

    if (generatedHash !== hmac) {
        return res.status(400).send("HMAC no válido");
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

    console.log("🔥 SHOP INSTALADO:");
    console.log("Shop:", shop);
    console.log("Access Token:", accessToken);

    shopsTokens[shop] = accessToken;
    console.log("Tokens guardados en memoria:", shopsTokens);

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
            console.log("🏪 Datos de la tienda obtenidos:", shopJson.shop.name);
            await saveShopToDB(shop, accessToken, shopJson.shop);
        }
    } catch (error) {
        console.error("⚠️ Error obteniendo datos de la tienda:", error);
    }

    return res.send(
        "Instalación completada. Ya puedes cerrar esta ventana."
    );
});

// ======================
// 7) TEST: VER ÓRDENES
// ======================
app.get("/shopify/orders-test", async (req, res) => {
    const shop =
        req.query.shop || req.headers["x-shopify-shop-domain"] || "";

    if (!shop) {
        return res.status(400).send("Falta el parámetro shop.");
    }

    const accessToken = shopsTokens[shop];
    if (!accessToken) {
        return res
            .status(401)
            .send("Esta tienda no está conectada todavía con PATHXPRESS.");
    }

    try {
        const apiVersion = "2024-07";
        const url = `https://${shop}/admin/api/${apiVersion}/orders.json?limit=5&status=any`;

        console.log("👉 Llamando a Shopify:", url);

        const response = await fetch(url, {
            method: "GET",
            headers: {
                "X-Shopify-Access-Token": accessToken,
                "Content-Type": "application/json",
            },
        });

        const text = await response.text();
        console.log("🔎 Respuesta Shopify:", response.status, text);

        let data;
        try {
            data = JSON.parse(text);
        } catch (e) {
            console.error("No se pudo parsear JSON:", e);
            return res
                .status(500)
                .send("Error parseando la respuesta de Shopify. Mira la consola.");
        }

        if (!response.ok) {
            return res
                .status(response.status)
                .send(
                    `<pre>Error de Shopify (${response.status}):\n${text}</pre>`
                );
        }

        const orders = data.orders || [];

        let html = `
      <html>
        <head><meta charset="utf-8"><title>Órdenes Shopify</title></head>
        <body style="font-family: Arial; padding: 20px;">
          <h1>Últimas órdenes de ${shop}</h1>
    `;

        if (orders.length === 0) {
            html += "<p>No hay órdenes todavía.</p>";
        } else {
            html += "<ul>";
            for (const order of orders) {
                html += `<li>#${order.name} – total: ${order.total_price} ${order.currency}</li>`;
            }
            html += "</ul>";
        }

        html += `
          <p><a href="/app?shop=${shop}">Volver a PATHXPRESS Portal</a></p>
        </body>
      </html>
    `;

        res.send(html);
    } catch (err) {
        console.error("Error leyendo órdenes de Shopify:", err);
        res
            .status(500)
            .send("Error al leer órdenes de Shopify (mira la consola).");
    }
});

// ======================
// 8) REGISTRO DEL WEBHOOK
// ======================
async function registerOrderWebhook(shop, accessToken) {
    const apiVersion = "2024-07";
    const webhookUrl = `${process.env.APP_URL}/webhooks/shopify/orders`;

    console.log("📡 Registrando webhook para tienda:", shop);
    console.log("📡 URL del webhook:", webhookUrl);

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
    console.log("🔔 Registro Webhook:", response.status, body);
}

// ======================
// 8.1) REGISTRO CARRIER SERVICE
// ======================
async function registerCarrierService(shop, accessToken) {
    const apiVersion = "2024-07";
    const callbackUrl = `${process.env.APP_URL}/api/shipping-rates`;

    console.log("🚚 Registrando CarrierService en:", shop);

    try {
        // 1. Verificar si ya existe
        const getRes = await fetch(`https://${shop}/admin/api/${apiVersion}/carrier_services.json`, {
            headers: { "X-Shopify-Access-Token": accessToken }
        });
        const getData = await getRes.json();
        const existing = (getData.carrier_services || []).find(cs => cs.name === "PathXpress Shipping");

        if (existing) {
            console.log("✅ CarrierService ya existe. ID:", existing.id);
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
            console.log("✅ CarrierService registrado exitosamente:", json.carrier_service.id);
        } else {
            console.error("⚠️ Error registrando CarrierService:", JSON.stringify(json));
        }
    } catch (err) {
        console.error("⛔ Excepción registrando CarrierService:", err);
    }
}

// ======================
// 9) ARRANCAR SERVIDOR
// ======================
app.listen(PORT, () => {
    console.log(
        `Servidor PATHXPRESS Shopify escuchando en http://localhost:${PORT}`
    );

    // Iniciar Cron/Intervalo de Sincronización (cada 60 segundos)
    setInterval(syncShipmentsToShopify, 60 * 1000);

    // Iniciar Cron de Reintentos (cada 5 minutos)
    setInterval(processRetryQueue, 5 * 60 * 1000);

    console.log("🔄 Sincronización automática iniciada (cada 60s).");
    console.log("🛡️ Sistema de reintentos iniciado (cada 5m).");
});

// ======================
// 11) SISTEMA DE REINTENTOS (Error Handling)
// ======================
async function processRetryQueue() {
    console.log("🛡️ Revisando cola de reintentos...");
    try {
        // Buscar items pendientes con menos de 5 intentos
        const [rows] = await db.execute(`
            SELECT * FROM webhook_retries 
            WHERE status = 'PENDING' AND retry_count < 5
            LIMIT 5
        `);

        if (rows.length === 0) return;

        console.log(`🛡️ Procesando ${rows.length} reintentos...`);

        for (const row of rows) {
            const { id, shop_domain, payload, retry_count } = row;

            try {
                // Parsear payload si viene como string
                let order = payload;
                if (typeof order === 'string') order = JSON.parse(order);

                console.log(`🔄 Reintentando orden ${order.name} (Intento ${retry_count + 1})...`);

                // 1. Obtener info tienda
                const shopData = await getShopFromDB(shop_domain);

                // 2. Procesar
                const shipment = orderToShipment(order, shop_domain, shopData);
                await saveShipmentToMySQL(shipment);
                await saveShipmentToOrdersTable(shipment);

                // 3. Marcar como procesado
                await db.execute("UPDATE webhook_retries SET status = 'PROCESSED', updated_at = NOW() WHERE id = ?", [id]);
                console.log(`✅ Reintento exitoso para ID ${id}`);

            } catch (err) {
                console.error(`⛔ Falló reintento ID ${id}:`, err.message);
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
        console.error("⛔ Error en ciclo de reintentos:", err);
    }
}

// ======================
// 10) LOGICA DE SINCRONIZACIÓN (Two-Way Sync)
// ======================
async function syncShipmentsToShopify() {
    console.log("🔄 Ejecutando sincronización de estados...");
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

        console.log(`🔄 Encontrados ${rows.length} envíos para sincronizar con Shopify.`);

        for (const row of rows) {
            await fulfillShopifyOrder(row);
        }

    } catch (err) {
        console.error("⛔ Error en ciclo de sincronización:", err);
    }
}

async function fulfillShopifyOrder(row) {
    const { shipment_id, shop_domain, shop_order_id, waybillNumber } = row;

    try {
        // 1. Obtener Token de la tienda
        const shopData = await getShopFromDB(shop_domain);
        if (!shopData || !shopData.access_token) {
            console.error(`⚠️ No hay token para ${shop_domain}, saltando.`);
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
            console.error(`⚠️ No se encontró Location ID para ${shop_domain}`);
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
            console.log(`ℹ️ La orden ${shop_order_id} no tiene fulfillment_orders abiertas. Marcamos como sync localmente.`);
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
            console.log(`✅ Fulfillment creado en Shopify: ${newFulfillmentId} para orden ${shop_order_id}`);

            // 4. Actualizar DB local
            await db.execute("UPDATE shopify_shipments SET shopify_fulfillment_id = ? WHERE id = ?", [newFulfillmentId, shipment_id]);
        } else {
            console.error(`⛔ Error creando fulfillment en Shopify:`, JSON.stringify(createJson));
        }

    } catch (err) {
        console.error(`⛔ Excepción sincronizando orden ${shop_order_id}:`, err);
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
        console.warn(`⚠️ La tienda ${shop} NO tiene configurado pathxpress_client_id. Usando default: 1`);
    }

    // Determinar Service Type
    // Buscamos en shipping_lines el título del servicio
    const shippingLines = order.shipping_lines || [];
    const shippingTitle = shippingLines.length > 0 ? shippingLines[0].title : "";

    let serviceType = "DOM"; // Default
    if (shopData?.service_mapping && shippingTitle) {
        // service_mapping puede venir como objeto o string JSON si la librería mysql2 no lo parsea auto
        let mapping = shopData.service_mapping;
        if (typeof mapping === 'string') {
            try { mapping = JSON.parse(mapping); } catch (e) { }
        }

        if (mapping && mapping[shippingTitle]) {
            serviceType = mapping[shippingTitle];
            console.log(`🚚 Mapeado servicio '${shippingTitle}' -> '${serviceType}'`);
        }
    }

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

