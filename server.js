const WebSocket = require("ws");
const http = require("http");
const url = require("url");
const crypto = require("crypto");
const rateLimit = require("express-rate-limit"); // For HTTP rate limiting
const express = require("express");

require("dotenv").config({ path: ".env" });

// Validate environment variables
const SHARED_SECRET = process.env.SHARED_SECRET;
const ALLOWED_ORIGINS = process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',').map(o => o.trim()) : [];
if (!SHARED_SECRET) {
  console.error('Fatal: SHARED_SECRET environment variable is missing');
  process.exit(1);
}
if (!ALLOWED_ORIGINS.length) {
  console.error('Fatal: ALLOWED_ORIGINS environment variable is missing or empty');
  process.exit(1);
}

// HTTP server with rate limiting
const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// Rate limit HTTP requests (including WebSocket upgrades)
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit to 100 requests per IP
  message: JSON.stringify({ error: "Too many requests" }),
});
app.use(limiter);

// Health check endpoint
app.get("/health", (req, res) => res.status(200).json({ status: "ok" }));

wss.on("connection", async (wsClient, request) => {
  try {
    console.log("React app connected to proxy");

    // Check Origin header
    const currentOrigin = request?.headers?.origin;
    if (!currentOrigin || !ALLOWED_ORIGINS.includes(currentOrigin)) {
      console.error(`Unauthorized origin: ${currentOrigin}`);
      wsClient.send(JSON.stringify({ error: 'Unauthorized origin' }));
      wsClient.close(1008, 'Unauthorized origin');
      return;
    }

    // Parse and validate query parameters
    const { query } = url.parse(request.url, true);
    const encrypted = query.data?.trim();
    const iv = query.iv?.trim();

    if (!encrypted || !iv) {
      console.error("Missing encrypted data or IV");
      wsClient.send(JSON.stringify({ error: "Missing encrypted data" }));
      wsClient.close(1008, "Missing encrypted data");
      return;
    }

    // Validate base64 format
    if (!/^[A-Za-z0-9+/=]+$/.test(encrypted) || !/^[A-Za-z0-9+/=]+$/.test(iv)) {
      console.error("Invalid base64 format in query parameters");
      wsClient.send(JSON.stringify({ error: "Invalid input format" }));
      wsClient.close(1008, "Invalid input format");
      return;
    }

    let payload;
    try {
      payload = await decryptPayload(encrypted, iv, SHARED_SECRET);
    } catch (err) {
      console.error("Decryption error:", err.message);
      wsClient.send(JSON.stringify({ error: "Failed to decrypt" }));
      wsClient.close(1008, "Failed to decrypt");
      return;
    }

    const { cookie, endpoint, origin, userAgent } = payload || {};
    if (!cookie || !endpoint) {
      console.error("Missing cookie or endpoint in decrypted payload");
      wsClient.send(JSON.stringify({ error: "Missing decrypted data" }));
      wsClient.close(1008, "Missing decrypted data");
      return;
    }

    // Validate endpoint URL
    if (!endpoint.startsWith("wss://")) {
      console.error("Invalid WebSocket endpoint:", endpoint);
      wsClient.send(JSON.stringify({ error: "Invalid endpoint" }));
      wsClient.close(1008, "Invalid endpoint");
      return;
    }

    // Sanitize headers
    const headers = {
      "Accept-Encoding": "gzip, deflate, br, zstd",
      "Accept-Language": "en-US,en;q=0.9",
      "Cache-Control": "no-cache",
      Connection: "Upgrade",
      Host: new URL(endpoint).host,
      Origin: origin || "https://chat.zalo.me",
      Pragma: "no-cache",
      "Sec-WebSocket-Extensions": "permessage-deflate; client_max_window_bits",
      "Sec-WebSocket-Version": "13",
      Upgrade: "websocket",
      "User-Agent":
        userAgent ||
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
      Cookie: cookie,
    };

    let targetWs;
    try {
      targetWs = new WebSocket(endpoint, { headers, timeout: 10000 });
    } catch (err) {
      console.error("Failed to create WebSocket:", err.message);
      wsClient.send(JSON.stringify({ error: "Failed to connect to target" }));
      wsClient.close(1011, "Failed to connect to target");
      return;
    }

    // Set connection timeout
    const timeout = setTimeout(() => {
      console.error("WebSocket connection timeout");
      wsClient.send(JSON.stringify({ error: "Connection timeout" }));
      wsClient.close(1011, "Connection timeout");
      targetWs.close(1011, "Connection timeout");
    }, 10000);

    targetWs.on("open", () => {
      clearTimeout(timeout);
      console.log("Connected to target server");
    });

    targetWs.on("message", (data, isBinary) => {
      if (wsClient.readyState === WebSocket.OPEN) {
        console.log("[LOG]: data length", data.length);
        wsClient.send(data, { binary: isBinary });
      }
    });

    wsClient.on("message", (data, isBinary) => {
      if (targetWs.readyState === WebSocket.OPEN) {
        targetWs.send(data, { binary: isBinary });
      }
    });

    targetWs.on("close", (code, reason) => {
      console.log(`Target closed: ${code} ${reason}`);
      wsClient.close(code, reason);
    });

    wsClient.on("close", (code, reason) => {
      console.log(`Client closed: ${code} ${reason}`);
      targetWs.close(code, reason);
    });

    targetWs.on("error", (error) => {
      console.error("Target error:", error.message);
      wsClient.send(JSON.stringify({ error: "Target server error" }));
      wsClient.close(1011, "Target server error");
    });

    wsClient.on("error", (error) => {
      console.error("Client error:", error.message);
      targetWs.close(1011, "Client error");
    });
  } catch (error) {
    console.error("Unexpected error:", error.message);
    wsClient.send(JSON.stringify({ error: "Server error" }));
    wsClient.close(1011, "Server error");
  }
});

const port = process.env.PORT || 8080;
server.listen(port, () =>
  console.log(`Proxy running on ws://localhost:${port}`)
);

async function decryptPayload(dataB64, ivB64, secretB64) {
  let data, iv, secret;
  try {
    data = Buffer.from(dataB64, "base64");
    iv = Buffer.from(ivB64, "base64");
    secret = Buffer.from(secretB64, "base64");
  } catch (err) {
    console.error("Base64 decode error:", err.message);
    throw new Error("Invalid base64 input");
  }

  if (iv.length !== 12) {
    throw new Error(`Invalid IV length: ${iv.length}, expected 12 bytes`);
  }
  if (secret.length !== 32) {
    throw new Error(`Invalid key length: ${secret.length}, expected 32 bytes`);
  }

  const authTag = data.slice(-16);
  const encryptedData = data.slice(0, -16);

  const decipher = crypto.createDecipheriv("aes-256-gcm", secret, iv);
  decipher.setAuthTag(authTag);

  let decrypted;
  try {
    decrypted = Buffer.concat([
      decipher.update(encryptedData),
      decipher.final(),
    ]);
  } catch (err) {
    console.error("Decryption error:", err.message);
    throw new Error("Decryption failed");
  }

  const decryptedStr = decrypted.toString("utf8");
  try {
    return JSON.parse(decryptedStr);
  } catch (err) {
    console.error("Invalid JSON after decryption:", decryptedStr);
    throw new Error("Invalid JSON data");
  }
}
