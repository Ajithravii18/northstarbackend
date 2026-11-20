import "dotenv/config";
import express from "express";
import cookieParser from "cookie-parser";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import path from "node:path";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import api from "./routes.js";
import { HttpError } from "./errors.js";
import { config } from "./config.js";

const app = express();
const isProduction = process.env.NODE_ENV === "production";
const rootDirectory = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: "draft-8",
  legacyHeaders: false,
  message: { success: false, code: "RATE_LIMITED", message: "Too many sign-in attempts. Try again later." },
});
const passwordRecoveryLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 5,
  standardHeaders: "draft-8",
  legacyHeaders: false,
  message: { success: false, code: "RATE_LIMITED", message: "Too many password recovery attempts. Try again later." },
});
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 300,
  standardHeaders: "draft-8",
  legacyHeaders: false,
});

const distributionDirectory = path.resolve(rootDirectory, "client", "dist");
const hasClientBuild = existsSync(distributionDirectory);

function corsForConfiguredOrigins(req, res, next) {
  const origin = req.get("origin");
  if (origin && !config.appOrigins.includes(origin)) {
    return res.status(403).json({ success: false, code: "ORIGIN_NOT_ALLOWED", message: "This request origin is not allowed." });
  }
  if (origin) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Access-Control-Allow-Credentials", "true");
    res.setHeader("Vary", "Origin");
  }
  if (req.method === "OPTIONS") {
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");
    return res.sendStatus(204);
  }
  next();
}

app.disable("x-powered-by");
app.set("trust proxy", isProduction ? 1 : false);
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        baseUri: ["'self'"],
        connectSrc: ["'self'"],
        fontSrc: ["'self'", "data:"],
        formAction: ["'self'"],
        frameAncestors: ["'none'"],
        imgSrc: ["'self'", "data:"],
        objectSrc: ["'none'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        upgradeInsecureRequests: isProduction ? [] : null,
      },
    },
    crossOriginEmbedderPolicy: false,
  }),
);
app.use(express.json({ limit: "32kb", strict: true }));
app.use(cookieParser());
app.use("/api", corsForConfiguredOrigins);
app.use("/api/auth/login", loginLimiter);
app.use("/api/auth/forgot-password", passwordRecoveryLimiter);
app.use("/api/auth/reset-password", passwordRecoveryLimiter);
app.use("/api", apiLimiter);
app.use("/api", api);

if (isProduction) {
  if (hasClientBuild) app.use(
    express.static(distributionDirectory, {
      index: false,
      maxAge: "1y",
      immutable: true,
      setHeaders(res, filePath) {
        if (filePath.endsWith(".html")) {
          res.setHeader("Cache-Control", "no-cache");
        }
      },
    }),
  );
  if (hasClientBuild) app.get("*", (req, res, next) => {
    if (
      req.path === "/api" ||
      req.path.startsWith("/api/") ||
      path.extname(req.path) ||
      !req.accepts("html")
    ) {
      return next();
    }
    res.sendFile(path.join(distributionDirectory, "index.html"));
  });
}

app.use((req, res, next) => {
  next(new HttpError(404, "The requested endpoint was not found.", "NOT_FOUND"));
});

app.use((error, req, res, next) => {
  if (res.headersSent) return next(error);
  if (error?.code === 11000) {
    return res.status(409).json({
      success: false,
      code: "DUPLICATE_VALUE",
      message: "A record with that name or email already exists.",
    });
  }
  if (error?.name === "CastError") {
    return res.status(400).json({ success: false, code: "INVALID_ID", message: "The requested ID is invalid." });
  }
  if (error?.name === "ValidationError") {
    return res.status(400).json({ success: false, code: "INVALID_RECORD", message: error.message });
  }
  if (error?.type === "entity.parse.failed") {
    return res.status(400).json({ success: false, code: "INVALID_JSON", message: "The request body is not valid JSON." });
  }
  const status = error instanceof HttpError ? error.status : 500;
  const code = error instanceof HttpError ? error.code : "INTERNAL_SERVER_ERROR";
  if (status >= 500) console.error("API request failed:", error);
  res.status(status).json({
    success: false,
    code,
    message: status >= 500 ? "An unexpected server error occurred." : error.message,
  });
});

export default app;
