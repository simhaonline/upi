// ===== server.js =====
const express = require("express");
const bodyParser = require("body-parser");
const crypto = require("crypto");
const axios = require("axios");
const helmet = require("helmet");
const morgan = require("morgan");
const path = require("path");

const app = express();
// Basic security headers + JSON parsing
app.use(helmet());
app.use(bodyParser.json());
app.use(morgan("dev"));

// Serve front-end files from /public
app.use(express.static(path.join(__dirname, "public")));

// ───  CONFIGURATION  ────────────────────────────────────────────────────────────
// (1) Sandbox credentials from wpay.one
const WPAY_HOST = "https://sandbox.wpay.one"; // base URL for sandbox
const MCH_ID = "1000";
const SECRET_KEY = "eb6080dbc8dc429ab86a1cd1c337975d";

// (2) Your public domain where you host this code
//     Make sure this matches exactly, including https://, no trailing slash.
const PUBLIC_DOMAIN = "https://pay.mehulbhatt.net";

// (3) The endpoint to receive pay-in callbacks
//     This must be reachable from sandbox.wpay.one; 
//     they will POST here ~10s after you create an order.
const PAYIN_CALLBACK_PATH = "/api/payin-callback";
const PAYIN_CALLBACK_URL = PUBLIC_DOMAIN + PAYIN_CALLBACK_PATH;

// ───  IN‐MEMORY  “DATABASE”  ───────────────────────────────────────────────────────
// In production, swap this out for a real DB (MySQL / Redis / etc.).
// orders[outTradeNo] = { amount, status, upiUrl, qrBase64, createdAt, lastCallbackData }
const orders = {};

// ───  UTILITY: MD5 SIGNING  ────────────────────────────────────────────────────────
// The sandbox docs say you must build a string of parameters in alphabetical order, concat them, 
// then append the key, then MD5 hex‐digest (uppercase).  
//
//   e.g. stringA = "amount=500&mchId=1000&notifyUrl=...&outTradeNo=1654321"; 
//        stringToSign = stringA + "&key=" + SECRET_KEY; 
//        sign = MD5(stringToSign).toUpperCase();
//
// NOTE: Always consult the exact Postman docs for parameter ordering & URL encoding details.
function md5Sign(paramsObject) {
  // 1) Extract keys, sort them lexographically
  const keys = Object.keys(paramsObject).sort();
  // 2) Build “key=value” pairs joined by &
  const kvPairs = keys.map((k) => `${k}=${paramsObject[k]}`);
  // 3) Append “key=<SECRET_KEY>”
  kvPairs.push(`key=${SECRET_KEY}`);
  // 4) MD5 → uppercase
  const rawString = kvPairs.join("&");
  const hash = crypto.createHash("md5").update(rawString, "utf8").digest("hex");
  return hash.toUpperCase();
}

// ───  ROUTE: POST /api/create-order  ───────────────────────────────────────────────
// Request JSON: { amount: number, outTradeNo?: string (optional) }
// If outTradeNo is not provided, we’ll generate a UUID‐style string.
app.post("/api/create-order", async (req, res) => {
  try {
    let { amount, outTradeNo } = req.body;
    if (!amount) {
      return res.status(400).json({ error: "Missing `amount` in request body." });
    }

    // 1) Generate a unique outTradeNo if none provided
    if (!outTradeNo) {
      // e.g. “MB20230531123045” or use current timestamp + random
      outTradeNo = "MB" + Date.now();
    }

    // 2) Build the parameters per wpay.one Postman docs.
    //    The “Create Order” API for a UPI‐type payin usually wants:
    //      mchId, outTradeNo, amount, currency (if required), subject, body (optional),
    //      notifyUrl (your callback), any ‘extra’ map (like payType=UPI),
    //      timestamp (if they require), nonceStr (if they require), etc.
    //
    //    Refer to the Postman collection to confirm the exact field names. 
    //    In our example, let’s assume the doc says:
    //      {
    //        mchId: "1000",
    //        outTradeNo: "XXXXXXXX",
    //        amount: "500",              // amount in rupees (string)
    //        payType: "UPI",             // because we want a UPI QR
    //        subject: "Order Payment",
    //        notifyUrl: "https://pay.mehulbhatt.net/api/payin-callback",
    //        timestamp: "20230531123045" // yyyymmddHHMMSS
    //      }
    //
    //    Then we sign exactly those fields (alphabetical sort), plus key=SECRET_KEY.

    const timestamp = new Date()
      .toISOString()
      .replace(/[-:TZ.]/g, "")
      .slice(0, 14); // “YYYYMMDDhhmmss”
    const params = {
      mchId: MCH_ID,
      outTradeNo: outTradeNo,
      amount: String(amount), // MUST be string
      payType: "UPI",
      subject: "Order Payment",
      notifyUrl: PAYIN_CALLBACK_URL,
      timestamp,
    };
    // Compute the signature
    const sign = md5Sign(params);
    // Attach signature to the payload
    const payload = { ...params, sign };

    // 3) Send the request to sandbox.wpay.one’s “Create Order” endpoint.
    //    Per their docs, it might be a POST to /pay/createOrder or /api/payin/create, etc.
    //    Look up the exact path in Postman. In our example, assume:
    //      POST https://sandbox.wpay.one/pay/createOrder
    //
    //    We need to set “Content-Type: application/json” and send `payload`.
    const wpayUrl = `${WPAY_HOST}/pay/createOrder`;
    const wpayResp = await axios.post(wpayUrl, payload, {
      headers: {
        "Content-Type": "application/json",
      },
    });

    // 4) wpay.one should respond with something like:
    //    {
    //      code: "SUCCESS",
    //      data: { 
    //        upiUrl: "upi://pay?pa=1234567890@upi&pn=Mehul&am=500", 
    //        qrCodeBase64: "<base64‐PNG data>" 
    //      },
    //      message: "Order created"
    //    }
    //
    //    Adjust based on the actual response schema.

    const { code, data, message } = wpayResp.data;
    if (code !== "SUCCESS") {
      return res.status(500).json({
        error: "wpay.one returned failure",
        details: wpayResp.data,
      });
    }

    // 5) Save this order in our in‐memory map
    orders[outTradeNo] = {
      amount,
      status: "CREATED", // CREATED → PENDING → PAID (or FAILED)
      upiUrl: data.upiUrl,
      qrBase64: data.qrCodeBase64, // if the API returned Base64 PNG
      createdAt: new Date(),
      lastCallbackData: null,
    };

    // 6) Return to front‐end: { outTradeNo, upiUrl, qrBase64 }
    return res.json({
      outTradeNo,
      upiUrl: data.upiUrl,
      qrBase64: data.qrCodeBase64,
    });
  } catch (err) {
    console.error("Error in /api/create-order:", err.response?.data || err.message);
    return res.status(500).json({ error: "Internal server error", details: err.message });
  }
});

// ───  ROUTE: POST /api/payin-callback  ───────────────────────────────────────────────
// This is the URL you provided in “notifyUrl” when creating the order.
// After wpay.one processes a payin, they will POST here (in ~10s) to tell you success/fail.
//
app.post("/api/payin-callback", (req, res) => {
  // Step A) Parse incoming JSON from wpay.one
  const callbackData = req.body;
  // Example payload might look like:
  // {
  //   mchId: "1000",
  //   outTradeNo: "MB1654034448371",
  //   amount: "500",
  //   payType: "UPI",
  //   tradeStatus: "SUCCESS", // or "FAILED"
  //   transactionId: "WPAY1234567890",
  //   timestamp: "20230531123100",
  //   sign: "ABCD1234EF567890..." 
  // }
  //
  // Step B) Verify that “mchId” matches our MCH_ID
  if (callbackData.mchId !== MCH_ID) {
    console.warn("Invalid mchId in callback:", callbackData);
    return res.status(400).send("invalid mchId");
  }
  // Step C) Extract the sign, then recompute MD5 on the rest of the fields
  const { sign: incomingSign, ...rest } = callbackData;
  const computedSign = md5Sign(rest);
  if (computedSign !== incomingSign) {
    console.warn("Signature mismatch on payin‐callback:", { incomingSign, computedSign });
    return res.status(400).send("invalid signature");
  }

  // Step D) Mark the order’s status based on “tradeStatus”
  const { outTradeNo, tradeStatus } = callbackData;
  if (!orders[outTradeNo]) {
    console.warn("Unknown outTradeNo in payin‐callback:", outTradeNo);
    // STILL respond 200 so wpay.one won’t retry?
    return res.status(200).send("unknown order");
  }

  orders[outTradeNo].lastCallbackData = callbackData;
  if (tradeStatus === "SUCCESS") {
    orders[outTradeNo].status = "PAID";
  } else {
    orders[outTradeNo].status = "FAILED";
  }

  // Step E) Respond with a plain 200 and body “SUCCESS” (or whatever the docs ask for)
  return res.status(200).send("SUCCESS");
});

// ───  ROUTE: POST /api/verify-utr  ───────────────────────────────────────────────────
// The front‐end will POST { outTradeNo: "...", utr: "XXXXXXXXXXXX" } after the user enters their UTR.
// You simply check if orders[outTradeNo].status === "PAID". If yes, return { status: "SUCCESS" }.
//
// NOTE: You can also ignore UTR entirely if you simply trust wpay.one’s callback, but your UI wants a field
//       so user can manually confirm. In that case, you can store utr in memory for record‐keeping.
app.post("/api/verify-utr", (req, res) => {
  const { outTradeNo, utr } = req.body;
  if (!outTradeNo || !utr) {
    return res.status(400).json({ error: "Missing outTradeNo or utr" });
  }
  if (!orders[outTradeNo]) {
    return res.status(404).json({ error: "Order not found" });
  }
  // Only allow 12‐digit numeric UTR
  if (!/^\d{12}$/.test(utr)) {
    return res.status(400).json({ error: "UTR must be exactly 12 digits" });
  }

  // Save the UTR on our order (for record)
  orders[outTradeNo].utr = utr;

  // Check status
  if (orders[outTradeNo].status === "PAID") {
    return res.json({ status: "SUCCESS" });
  } else if (orders[outTradeNo].status === "FAILED") {
    return res.json({ status: "FAILED" });
  } else {
    // If still “CREATED” → “PENDING”
    return res.json({ status: "PENDING" });
  }
});

// ───  (Optional) ROUTE: GET /api/order-status/:outTradeNo  ───────────────────────────── 
// If you want to let the front‐end poll for status instead of having user enter UTR
app.get("/api/order-status/:outTradeNo", (req, res) => {
  const outTradeNo = req.params.outTradeNo;
  if (!orders[outTradeNo]) {
    return res.status(404).json({ error: "Order not found" });
  }
  return res.json({
    outTradeNo,
    status: orders[outTradeNo].status,
    createdAt: orders[outTradeNo].createdAt,
  });
});

// ───  CATCH‐ALL TO SERVE FRONT‐END  ─────────────────────────────────────────────────────
// Any other GET → return index.html
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public/index.html"));
});

// ───  START SERVER  ───────────────────────────────────────────────────────────────────
const HTTP_PORT = 8443; // or 443 if you run as root and have SSL; for testing, 8443 is fine.
app.listen(HTTP_PORT, () => {
  console.log(`🚀 UPI pay‐in server listening on port ${HTTP_PORT}`);
  console.log(` - create‐order: POST https://localhost:${HTTP_PORT}/api/create-order`);
  console.log(` - payin‐callback: POST https://localhost:${HTTP_PORT}${PAYIN_CALLBACK_PATH}`);
  console.log(` - verify‐utr: POST https://localhost:${HTTP_PORT}/api/verify-utr`);
});
