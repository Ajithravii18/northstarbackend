export class HttpError extends Error {
  constructor(status, message, code = "REQUEST_FAILED") {
    super(message);
    this.name = "HttpError";
    this.status = status;
    this.code = code;
  }
}

export const asyncRoute = (handler) => (req, res, next) =>
  Promise.resolve(handler(req, res, next)).catch(next);

export function parseInput(schema, input) {
  const parsed = schema.safeParse(input);
  if (!parsed.success) {
    const message = parsed.error.issues
      .map((issue) => `${issue.path.join(".") || "request"}: ${issue.message}`)
      .join("; ");
    throw new HttpError(400, message, "INVALID_REQUEST");
  }
  return parsed.data;
}

export function parseBody(schema, req) {
  return parseInput(schema, req.body);
}
