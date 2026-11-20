import mongoose from "mongoose";
import { isMemoryDevelopment } from "./config.js";

let memoryServer;

export async function connectDatabase() {
  let uri = process.env.MONGODB_URI;

  if (!uri && isMemoryDevelopment) {
    const { MongoMemoryReplSet } = await import("mongodb-memory-server");
    memoryServer = await MongoMemoryReplSet.create({ replSet: { count: 1 } });
    uri = memoryServer.getUri();
    console.info("Using an ephemeral MongoDB database for this development session.");
  }

  if (!uri) {
    throw new Error("Set MONGODB_URI to a MongoDB connection string before starting the API.");
  }

  await mongoose.connect(uri, { serverSelectionTimeoutMS: 10000 });
  return mongoose.connection;
}

export async function inTransaction(operation) {
  const session = await mongoose.startSession();
  try {
    let result;
    await session.withTransaction(async () => {
      result = await operation(session);
    });
    return result;
  } finally {
    await session.endSession();
  }
}

export async function closeDatabase() {
  await mongoose.disconnect();
  if (memoryServer) {
    await memoryServer.stop();
    memoryServer = undefined;
  }
}
