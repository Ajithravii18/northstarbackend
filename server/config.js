import "dotenv/config";
import { randomBytes } from "node:crypto";

export const isMemoryDevelopment = process.argv.includes("--dev-memory");
const isProduction = process.env.NODE_ENV === "production";

const generatedJwtSecret = isMemoryDevelopment ? randomBytes(48).toString("base64url") : null;
const generatedBootstrapToken = isMemoryDevelopment ? randomBytes(32).toString("base64url") : null;
const configuredOrigins = process.env.APP_ORIGINS || "http://127.0.0.1:5173,http://localhost:5173";
const appOrigins = configuredOrigins
  .split(",")
  .map((origin) => origin.trim())
  .filter(Boolean);
const resendApiKey = process.env.RESEND_API_KEY?.trim() || null;
const passwordResetFromEmail = process.env.PASSWORD_RESET_FROM_EMAIL?.trim() || null;

export const config = {
  port: Number(process.env.PORT ?? 4000),
  jwtSecret: process.env.JWT_SECRET || generatedJwtSecret,
  bootstrapToken: process.env.ADMIN_BOOTSTRAP_TOKEN || generatedBootstrapToken,
  cookieSecure: !isMemoryDevelopment,
  cookieSameSite: isMemoryDevelopment ? "lax" : "none",
  appOrigins,
  resendApiKey,
  passwordResetFromEmail,
};

if (isMemoryDevelopment && isProduction) {
  throw new Error("The ephemeral --dev-memory mode cannot be used with NODE_ENV=production.");
}

if (!Number.isInteger(config.port) || config.port < 1 || config.port > 65535) {
  throw new Error("PORT must be a valid TCP port.");
}

if (!config.jwtSecret || config.jwtSecret.length < 32) {
  throw new Error("Set JWT_SECRET to a random secret of at least 32 characters.");
}

if (!config.bootstrapToken || config.bootstrapToken.length < 32) {
  throw new Error("Set ADMIN_BOOTSTRAP_TOKEN to a random secret of at least 32 characters.");
}

if (config.jwtSecret === config.bootstrapToken) {
  throw new Error("JWT_SECRET and ADMIN_BOOTSTRAP_TOKEN must be different values.");
}

if (Boolean(config.resendApiKey) !== Boolean(config.passwordResetFromEmail)) {
  throw new Error("Configure both RESEND_API_KEY and PASSWORD_RESET_FROM_EMAIL for password recovery.");
}

if (config.passwordResetFromEmail && !/^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$/.test(config.passwordResetFromEmail)) {
  throw new Error("PASSWORD_RESET_FROM_EMAIL must be a valid email address on a domain verified with Resend.");
}

if (!isMemoryDevelopment && !isProduction) {
  throw new Error("Set NODE_ENV=production for the persistent API, or use npm run dev locally.");
}

if (!isMemoryDevelopment && !process.env.APP_ORIGINS) {
  throw new Error("Set APP_ORIGINS to the exact HTTPS origin(s) serving the application.");
}

if (isProduction && (!config.resendApiKey || !config.passwordResetFromEmail)) {
  throw new Error("Set RESEND_API_KEY and PASSWORD_RESET_FROM_EMAIL to enable production password recovery.");
}

if (config.appOrigins.length === 0) {
  throw new Error("APP_ORIGINS must contain at least one allowed application origin.");
}

for (const origin of config.appOrigins) {
  let parsedOrigin;
  try {
    parsedOrigin = new URL(origin);
  } catch {
    throw new Error(`APP_ORIGINS contains an invalid origin: ${origin}`);
  }
  if (parsedOrigin.origin !== origin || (isProduction && parsedOrigin.protocol !== "https:")) {
    throw new Error("APP_ORIGINS must contain exact origins without paths; production origins must use HTTPS.");
  }
}

if (isMemoryDevelopment) {
  if (process.env.ADMIN_BOOTSTRAP_TOKEN) {
    console.info("Using the configured ADMIN_BOOTSTRAP_TOKEN for first-admin setup.");
  } else {
    console.info(`Development-only first-admin setup token: ${config.bootstrapToken}`);
  }
}
