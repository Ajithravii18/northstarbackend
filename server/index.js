import "dotenv/config";
import app from "./app.js";
import { connectDatabase, closeDatabase } from "./db.js";
import { config, isMemoryDevelopment } from "./config.js";
import { seedDevelopmentData } from "./devSeed.js";

let server;

async function start() {
  await connectDatabase();
  if (isMemoryDevelopment) await seedDevelopmentData();
  server = app.listen(config.port, "0.0.0.0", () => {
    console.info(`Access-control API listening on port ${config.port}.`);
    if (isMemoryDevelopment) console.info("Development login: create the first administrator from the app setup page.");
  });
}

async function shutdown(signal) {
  console.info(`${signal} received; closing the server.`);
  if (server) {
    await new Promise((resolve) => server.close(resolve));
  }
  await closeDatabase();
  process.exit(0);
}

process.once("SIGINT", () => void shutdown("SIGINT"));
process.once("SIGTERM", () => void shutdown("SIGTERM"));

start().catch((error) => {
  console.error("The access-control API could not start:", error.message);
  process.exitCode = 1;
});
