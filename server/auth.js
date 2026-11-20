import jwt from "jsonwebtoken";
import { config } from "./config.js";
import { HttpError, asyncRoute } from "./errors.js";
import { Role, User } from "./models.js";

export const cookieName = "northstar_access";

export function setAuthCookie(res, token) {
  res.cookie(cookieName, token, {
    httpOnly: true,
    secure: config.cookieSecure,
    sameSite: config.cookieSameSite,
    path: "/",
    maxAge: 8 * 60 * 60 * 1000,
  });
}

export function clearAuthCookie(res) {
  res.clearCookie(cookieName, {
    httpOnly: true,
    secure: config.cookieSecure,
    sameSite: config.cookieSameSite,
    path: "/",
  });
}

export function createAuthToken(user) {
  return jwt.sign({ sub: user._id.toString(), sv: user.sessionVersion ?? 0 }, config.jwtSecret, {
    expiresIn: "8h",
    issuer: "northstar-access-control",
    audience: "northstar-web",
  });
}

export const requireAuth = asyncRoute(async (req, res, next) => {
  const token = req.cookies[cookieName];
  if (!token) throw new HttpError(401, "Please sign in to continue.", "AUTHENTICATION_REQUIRED");

  let claims;
  try {
    claims = jwt.verify(token, config.jwtSecret, {
      issuer: "northstar-access-control",
      audience: "northstar-web",
    });
  } catch {
    clearAuthCookie(res);
    throw new HttpError(401, "Your session has expired. Please sign in again.", "SESSION_EXPIRED");
  }

  if (typeof claims === "string" || typeof claims.sub !== "string") {
    clearAuthCookie(res);
    throw new HttpError(401, "Your session is invalid. Please sign in again.", "INVALID_SESSION");
  }

  const user = await User.findById(claims.sub);
  const role = user?.roleId ? await Role.findById(user.roleId) : null;
  if (!user || (claims.sv ?? 0) !== (user.sessionVersion ?? 0)) {
    clearAuthCookie(res);
    throw new HttpError(401, "Your session has been revoked. Please sign in again.", "SESSION_REVOKED");
  }
  if (!user.isActive || !role || role.status !== "ACTIVE") {
    clearAuthCookie(res);
    throw new HttpError(401, "Your account or role is no longer active.", "ACCOUNT_INACTIVE");
  }

  req.user = user;
  req.role = role;
  next();
});

export const requireSystemAdministrator = (req, res, next) => {
  if (!req.role || req.role.name !== "System Administrator" || req.role.status !== "ACTIVE") {
    return next(new HttpError(403, "Only an active System Administrator can manage access control.", "FORBIDDEN"));
  }
  next();
};

