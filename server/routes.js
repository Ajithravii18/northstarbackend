import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import bcrypt from "bcryptjs";
import mongoose from "mongoose";
import { Router } from "express";
import { config, isMemoryDevelopment } from "./config.js";
import { ACTIONS, ALL_PERMISSIONS, MODULES } from "./constants.js";
import { clearAuthCookie, createAuthToken, requireAuth, requireSystemAdministrator, setAuthCookie } from "./auth.js";
import { HttpError, asyncRoute, parseBody, parseInput } from "./errors.js";
import { inTransaction } from "./db.js";
import { sendPasswordResetEmail } from "./email.js";
import { AuditLog, Branch, Role, User } from "./models.js";
import { scopeFromLabel } from "./constants.js";
import { serializeAudit, serializeRole, serializeRoles, serializeUsers, writeAudit } from "./serializers.js";
import {
  assignmentSchema,
  cloneSchema,
  createUserSchema,
  forgotPasswordSchema,
  loginSchema,
  permissionsUpdateSchema,
  roleSchema,
  resetPasswordSchema,
  setupSchema,
  statusUpdateSchema,
} from "./validation.js";

const api = Router();
const dummyPasswordHash = bcrypt.hash(randomBytes(32).toString("hex"), 12);

function checkOrigin(req, res, next) {
  const origin = req.get("origin");
  if (origin && !config.appOrigins.includes(origin)) {
    return next(new HttpError(403, "This request origin is not allowed.", "ORIGIN_NOT_ALLOWED"));
  }
  next();
}

function frontendRoleInput(body) {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    throw new HttpError(400, "The request body must be an object.", "INVALID_REQUEST");
  }
  const permissions = {};
  if (body.permissions && typeof body.permissions === "object" && !Array.isArray(body.permissions)) {
    for (const [moduleName, grants] of Object.entries(body.permissions)) {
      const apiModule = moduleName === "RD" ? "RD" : moduleName.toUpperCase();
      permissions[apiModule] = Array.isArray(grants)
        ? grants.map((action) => (typeof action === "string" ? action.toUpperCase() : action))
        : grants;
    }
  } else {
    permissions.value = body.permissions;
  }
  return {
    ...body,
    status:
      body.status === "Active" || body.status === "ACTIVE"
        ? "ACTIVE"
        : body.status === "Inactive" || body.status === "INACTIVE"
          ? "INACTIVE"
          : body.status,
    branchScope: scopeFromLabel[body.branchScope] ?? body.branchScope,
    permissions,
  };
}

function parseRoleInput(req) {
  return parseInput(roleSchema, frontendRoleInput(req.body));
}

function hasPermissions(permissions) {
  return ACTIONS.some((action) =>
    MODULES.some((moduleName) => permissions[moduleName]?.includes(action)),
  );
}

function permissionsEqual(left, right) {
  return MODULES.every((moduleName) => {
    const a = [...(left?.[moduleName] ?? [])].sort();
    const b = [...(right?.[moduleName] ?? [])].sort();
    return a.length === b.length && a.every((action, index) => action === b[index]);
  });
}

async function validateBranchScope(scope, branchIds, session) {
  const uniqueIds = [...new Set(branchIds)];
  if (uniqueIds.length !== branchIds.length) {
    throw new HttpError(400, "A branch can only be selected once.", "INVALID_BRANCH_SCOPE");
  }
  if (scope === "SELECTED_BRANCHES" && branchIds.length === 0) {
    throw new HttpError(400, "Select at least one branch for this scope.", "INVALID_BRANCH_SCOPE");
  }
  if (branchIds.length) {
    const query = Branch.countDocuments({ _id: { $in: branchIds }, isActive: true });
    if (session) query.session(session);
    const activeCount = await query;
    if (activeCount !== branchIds.length) {
      throw new HttpError(400, "One or more selected branches were not found or are inactive.", "INVALID_BRANCH_SCOPE");
    }
  }
}

function assertRolePermissions(permissions) {
  if (!hasPermissions(permissions)) {
    throw new HttpError(400, "A role must have at least one permission.", "PERMISSION_REQUIRED");
  }
}

async function sessionUser(user, role) {
  let branchName = "All Branches / Central";
  if (user.branchId) {
    const branch = await Branch.findById(user.branchId).lean();
    if (branch) branchName = branch.name;
  }
  const serialized = role ? serializeRole(role) : null;
  return {
    id: user._id.toString(),
    name: user.name,
    email: user.email,
    roleName: role ? role.name : "Unassigned",
    isSystemAdministrator: role ? role.name === "System Administrator" : false,
    branchName,
    branchId: user.branchId || null,
    approvalLevel: role?.approvalLevel ?? 1,
    approvalLimit: role?.approvalLimit ?? null,
    permissions: serialized?.permissions || {},
  };
}

async function issueSession(res, user, role) {
  const token = createAuthToken(user);
  setAuthCookie(res, token);
  return await sessionUser(user, role);
}

function isValidBootstrapToken(candidate) {
  const expected = Buffer.from(config.bootstrapToken);
  const received = Buffer.from(candidate);
  return expected.length === received.length && timingSafeEqual(expected, received);
}

async function createAdministratorRole(session) {
  let role = await Role.findOne({ normalizedName: "system administrator" }).session(session);
  if (!role) {
    role = new Role({
      name: "System Administrator",
      normalizedName: "system administrator",
      description: "Full access to every module and system configuration.",
      status: "ACTIVE",
      branchScope: "ALL_BRANCHES",
      branchIds: [],
      approvalLevel: 3,
      approvalLimit: null,
      permissions: ALL_PERMISSIONS,
    });
    await role.save({ session });
    await AuditLog.create(
      [{ action: "Role created", target: role.name, actor: "System setup", metadata: {} }],
      { session },
    );
  }
  return role;
}

api.get(
  "/health",
  asyncRoute(async (_req, res) => {
    if (mongoose.connection.readyState !== 1) {
      return res.status(503).json({ success: false, status: "not_ready" });
    }
    res.json({ success: true, status: "ok" });
  }),
);

api.get(
  "/health/live",
  (_req, res) => res.json({ success: true, status: "ok" }),
);

api.get(
  "/auth/status",
  asyncRoute(async (req, res) => {
    const administratorRole = await Role.findOne({ normalizedName: "system administrator" }).select("_id");
    const setupComplete = administratorRole
      ? await User.exists({ roleId: administratorRole._id, passwordHash: { $exists: true } })
      : false;
    res.json({
      success: true,
      setupRequired: !setupComplete,
    });
  }),
);

api.post(
  "/auth/setup",
  checkOrigin,
  asyncRoute(async (req, res) => {
    const input = parseBody(setupSchema, req);
    if (!isValidBootstrapToken(input.token)) {
      throw new HttpError(403, "The setup token is invalid.", "INVALID_BOOTSTRAP_TOKEN");
    }

    const passwordHash = await bcrypt.hash(input.password, 12);
    const initialized = await inTransaction(async (session) => {
      const administratorRole = await createAdministratorRole(session);
      const alreadyInitialized = await User.exists({
        roleId: administratorRole._id,
        passwordHash: { $exists: true },
      }).session(session);
      if (alreadyInitialized) {
        throw new HttpError(409, "Initial administrator setup has already been completed.", "SETUP_COMPLETE");
      }

      const hasCentralBranch = await Branch.exists({ _id: "central", isActive: true }).session(session);
      const user = new User({
        name: input.name,
        email: input.email,
        normalizedEmail: input.email.trim().toLowerCase(),
        passwordHash,
        roleId: administratorRole._id,
        branchId: hasCentralBranch ? "central" : null,
        isActive: true,
      });
      await user.save({ session });
      await writeAudit(
        { user },
        "Administrator account created",
        user.email,
        {},
        session,
      );
      return { user, role: administratorRole };
    });
    const userSummary = await issueSession(res, initialized.user, initialized.role);
    res.status(201).json({ success: true, user: userSummary });
  }),
);

api.post(
  "/auth/login",
  checkOrigin,
  asyncRoute(async (req, res) => {
    const input = parseBody(loginSchema, req);
    const user = await User.findOne({ normalizedEmail: input.email.trim().toLowerCase() }).select("+passwordHash");
    if (!user || !user.passwordHash) {
      await bcrypt.compare(input.password, await dummyPasswordHash);
      throw new HttpError(401, "Incorrect email or password.", "INVALID_CREDENTIALS");
    }
    const passwordMatches = await bcrypt.compare(input.password, user.passwordHash);
    if (!passwordMatches || !user.isActive) {
      throw new HttpError(401, "Incorrect email or password.", "INVALID_CREDENTIALS");
    }
    const role = user.roleId ? await Role.findById(user.roleId) : null;
    if (!role || role.status !== "ACTIVE") {
      throw new HttpError(403, "Your account does not have an active role.", "ROLE_INACTIVE");
    }
    const userSummary = await issueSession(res, user, role);
    res.json({ success: true, user: userSummary });
  }),
);

api.post(
  "/auth/forgot-password",
  checkOrigin,
  asyncRoute(async (req, res) => {
    const input = parseBody(forgotPasswordSchema, req);
    const user = await User.findOne({
      normalizedEmail: input.email.trim().toLowerCase(),
      passwordHash: { $exists: true },
    }).select("_id email");

    if (user) {
      const token = randomBytes(32).toString("hex");
      const tokenHash = createHash("sha256").update(token).digest("hex");
      await User.updateOne(
        { _id: user._id },
        {
          $set: {
            passwordResetTokenHash: tokenHash,
            passwordResetExpiresAt: new Date(Date.now() + 30 * 60 * 1000),
          },
        },
      );

      const resetUrl = new URL("/reset-password", config.appOrigins[0]);
      resetUrl.searchParams.set("token", token);
      if (isMemoryDevelopment) {
        console.info(`Development-only password reset link: ${resetUrl.toString()}`);
      } else {
        try {
          await sendPasswordResetEmail(user.email, resetUrl);
        } catch (error) {
          await User.updateOne(
            { _id: user._id, passwordResetTokenHash: tokenHash },
            { $unset: { passwordResetTokenHash: "", passwordResetExpiresAt: "" } },
          );
          console.error("Password-reset email delivery failed.", {
            userId: user._id.toString(),
            error: error instanceof Error ? error.message : "Unknown delivery error",
          });
        }
      }
    }

    res.status(202).json({
      success: true,
      message: "If an account exists for that address, recovery instructions will be provided.",
      developmentLinkInConsole: isMemoryDevelopment,
    });
  }),
);

api.post(
  "/auth/reset-password",
  checkOrigin,
  asyncRoute(async (req, res) => {
    const input = parseBody(resetPasswordSchema, req);
    const tokenHash = createHash("sha256").update(input.token).digest("hex");
    const passwordHash = await bcrypt.hash(input.password, 12);
    const user = await inTransaction(async (session) => {
      const account = await User.findOneAndUpdate(
        {
          passwordResetTokenHash: tokenHash,
          passwordResetExpiresAt: { $gt: new Date() },
          passwordHash: { $exists: true },
        },
        {
          $set: { passwordHash },
          $inc: { sessionVersion: 1 },
          $unset: {
            passwordResetTokenHash: "",
            passwordResetExpiresAt: "",
          },
        },
        { new: true, session },
      );
      if (!account) return null;
      await writeAudit({ user: account }, "Password reset", account.email, {}, session);
      return account;
    });

    if (!user) {
      throw new HttpError(400, "This reset link is invalid or has expired.", "RESET_TOKEN_INVALID");
    }
    clearAuthCookie(res);
    res.json({ success: true });
  }),
);

api.post(
  "/auth/logout",
  checkOrigin,
  asyncRoute(async (req, res) => {
    clearAuthCookie(res);
    res.json({ success: true });
  }),
);

api.get(
  "/auth/me",
  requireAuth,
  asyncRoute(async (req, res) => {
    res.json({ success: true, user: await sessionUser(req.user, req.role) });
  }),
);

api.use(requireAuth, requireSystemAdministrator);

api.get(
  "/permissions",
  asyncRoute(async (req, res) => {
    res.json({ success: true, modules: MODULES, actions: ACTIONS });
  }),
);

api.get(
  "/branches",
  asyncRoute(async (req, res) => {
    const branches = await Branch.find({ isActive: true }).sort({ name: 1 }).lean();
    res.json({
      success: true,
      branches: branches.map((branch) => ({ id: branch._id, name: branch.name })),
    });
  }),
);

api.get(
  "/roles",
  asyncRoute(async (req, res) => {
    const roles = await Role.find().sort({ createdAt: -1 }).lean();
    res.json({ success: true, roles: await serializeRoles(roles) });
  }),
);

api.get(
  "/roles/:id",
  asyncRoute(async (req, res) => {
    const role = await Role.findById(req.params.id);
    if (!role) throw new HttpError(404, "Role not found.", "ROLE_NOT_FOUND");
    const userIds = await User.find({ roleId: role._id }).select("_id").lean();
    res.json({
      success: true,
      role: serializeRole(role, userIds.map((user) => user._id.toString())),
    });
  }),
);

api.post(
  "/roles",
  checkOrigin,
  asyncRoute(async (req, res) => {
    const input = parseRoleInput(req);
    if (input.name.toLowerCase() === "system administrator") {
      throw new HttpError(409, "The protected System Administrator role already exists.", "PROTECTED_ROLE");
    }
    assertRolePermissions(input.permissions);
    await validateBranchScope(input.branchScope, input.branchIds);

    const role = new Role({
      ...input,
      normalizedName: input.name.trim().toLocaleLowerCase("en-US"),
    });
    await inTransaction(async (session) => {
      await role.save({ session });
      await writeAudit(req, "Role created", role.name, {}, session);
    });
    res.status(201).json({ success: true, role: serializeRole(role) });
  }),
);

api.put(
  "/roles/:id",
  checkOrigin,
  asyncRoute(async (req, res) => {
    const input = parseRoleInput(req);
    const result = await inTransaction(async (session) => {
      const role = await Role.findById(req.params.id).session(session);
      if (!role) throw new HttpError(404, "Role not found.", "ROLE_NOT_FOUND");
      if (role.name === "System Administrator") {
        if (input.name !== role.name || input.status !== "ACTIVE" || input.branchScope !== "ALL_BRANCHES") {
          throw new HttpError(403, "The protected administrator role must remain active with all-branch scope.", "PROTECTED_ROLE");
        }
        if (!permissionsEqual(input.permissions, role.permissions.toObject())) {
          throw new HttpError(403, "System Administrator permissions cannot be modified.", "PROTECTED_ROLE");
        }
      }
      assertRolePermissions(input.permissions);
      await validateBranchScope(input.branchScope, input.branchIds, session);

      const previous = {
        status: role.status,
        permissions: role.permissions.toObject(),
        branchScope: role.branchScope,
        branchIds: [...role.branchIds],
        approvalLevel: role.approvalLevel,
        approvalLimit: role.approvalLimit,
      };
      role.set({
        ...input,
        normalizedName: input.name.trim().toLocaleLowerCase("en-US"),
      });
      await role.save({ session });
      await writeAudit(req, "Role updated", role.name, {}, session);
      if (!permissionsEqual(previous.permissions, input.permissions)) {
        await writeAudit(req, "Permission changed", role.name, { before: previous.permissions, after: input.permissions }, session);
      }
      if (previous.branchScope !== input.branchScope || previous.branchIds.join() !== input.branchIds.join()) {
        await writeAudit(req, "Branch scope changed", role.name, { before: { scope: previous.branchScope, branchIds: previous.branchIds }, after: { scope: input.branchScope, branchIds: input.branchIds } }, session);
      }
      if (previous.approvalLevel !== input.approvalLevel || previous.approvalLimit !== input.approvalLimit) {
        await writeAudit(req, "Approval settings changed", role.name, { before: { level: previous.approvalLevel, limit: previous.approvalLimit }, after: { level: input.approvalLevel, limit: input.approvalLimit } }, session);
      }
      if (previous.status !== input.status) {
        await writeAudit(req, `Role ${input.status.toLowerCase()}`, role.name, {}, session);
      }

      const userIds = await User.find({ roleId: role._id }).select("_id").session(session).lean();
      return { role, userIds: userIds.map((user) => user._id.toString()) };
    });
    res.json({ success: true, role: serializeRole(result.role, result.userIds) });
  }),
);

api.patch(
  "/roles/:id/status",
  checkOrigin,
  asyncRoute(async (req, res) => {
    const { status } = parseBody(statusUpdateSchema, req);
    const role = await inTransaction(async (session) => {
      const record = await Role.findById(req.params.id).session(session);
      if (!record) throw new HttpError(404, "Role not found.", "ROLE_NOT_FOUND");
      if (record.name === "System Administrator" && status !== "ACTIVE") {
        throw new HttpError(403, "The protected System Administrator role cannot be deactivated.", "PROTECTED_ROLE");
      }
      record.status = status;
      await record.save({ session });
      await writeAudit(req, `Role ${status.toLowerCase()}`, record.name, {}, session);
      return record;
    });
    res.json({ success: true, role: serializeRole(role) });
  }),
);

api.post(
  "/roles/:id/clone",
  checkOrigin,
  asyncRoute(async (req, res) => {
    const { name } = parseBody(cloneSchema, req);
    const role = await inTransaction(async (session) => {
      const source = await Role.findById(req.params.id).session(session).lean();
      if (!source) throw new HttpError(404, "Role not found.", "ROLE_NOT_FOUND");
      const duplicate = await Role.exists({ normalizedName: name.trim().toLocaleLowerCase("en-US") }).session(session);
      if (duplicate) throw new HttpError(409, "A role with this name already exists.", "DUPLICATE_ROLE_NAME");

      const record = new Role({
        name,
        normalizedName: name.trim().toLocaleLowerCase("en-US"),
        description: source.description,
        status: source.status,
        branchScope: source.branchScope,
        branchIds: source.branchIds,
        approvalLevel: source.approvalLevel,
        approvalLimit: source.approvalLimit,
        permissions: source.permissions,
      });
      await record.save({ session });
      await writeAudit(req, "Role cloned", record.name, { sourceRoleId: source._id.toString() }, session);
      return record;
    });
    res.status(201).json({ success: true, role: serializeRole(role) });
  }),
);

api.put(
  "/roles/:id/permissions",
  checkOrigin,
  asyncRoute(async (req, res) => {
    const { permissions } = parseBody(permissionsUpdateSchema, req);
    assertRolePermissions(permissions);
    const role = await inTransaction(async (session) => {
      const record = await Role.findById(req.params.id).session(session);
      if (!record) throw new HttpError(404, "Role not found.", "ROLE_NOT_FOUND");
      if (record.name === "System Administrator") {
        throw new HttpError(403, "System Administrator permissions cannot be modified.", "PROTECTED_ROLE");
      }
      record.permissions = permissions;
      await record.save({ session });
      await writeAudit(req, "Permission changed", record.name, {}, session);
      return record;
    });
    res.json({ success: true, role: serializeRole(role) });
  }),
);

api.put(
  "/roles/:id/users",
  checkOrigin,
  asyncRoute(async (req, res) => {
    const { userIds } = parseBody(assignmentSchema, req);
    if (new Set(userIds).size !== userIds.length) {
      throw new HttpError(400, "A user can only be assigned once.", "INVALID_ASSIGNMENT");
    }
    await inTransaction(async (session) => {
      const role = await Role.findById(req.params.id).session(session);
      if (!role) throw new HttpError(404, "Role not found.", "ROLE_NOT_FOUND");
      if (role.status !== "ACTIVE") {
        throw new HttpError(409, "Inactive roles cannot be assigned to users.", "ROLE_INACTIVE");
      }
      const administratorRole = await Role.findOne({ normalizedName: "system administrator" }).select("_id").session(session);
      if (!administratorRole) throw new HttpError(409, "The System Administrator role is missing.", "SYSTEM_ADMINISTRATOR_MISSING");
      if (role._id.toString() === administratorRole._id.toString()) {
        throw new HttpError(403, "Administrator accounts cannot be assigned through bulk role assignment.", "PROTECTED_ROLE");
      }

      const users = await User.find({ _id: { $in: userIds } })
        .select("_id isActive roleId")
        .session(session)
        .lean();
      if (users.length !== userIds.length) {
        throw new HttpError(400, "One or more users were not found.", "INVALID_ASSIGNMENT");
      }
      if (users.some((user) => !user.isActive && user.roleId?.toString() !== role._id.toString())) {
        throw new HttpError(400, "Inactive users cannot be newly assigned to a role.", "INVALID_ASSIGNMENT");
      }

      const movingAdminCount = await User.countDocuments({ _id: { $in: userIds }, roleId: administratorRole._id, isActive: true }).session(session);
      const currentAdminCount = await User.countDocuments({ roleId: administratorRole._id, isActive: true }).session(session);
      const remainingAdministrators = currentAdminCount - movingAdminCount;
      if (remainingAdministrators === 0) {
        throw new HttpError(409, "At least one active System Administrator account must remain.", "LAST_ADMINISTRATOR");
      }

      // Touch the protected role document so concurrent admin removals serialize
      // and re-evaluate the count after acquiring the write conflict.
      if (movingAdminCount > 0) {
        await Role.updateOne({ _id: administratorRole._id }, { $inc: { adminLockVersion: 1 } }, { session });
      }
      await User.updateMany(
        { roleId: role._id, _id: { $nin: userIds } },
        { $set: { roleId: null } },
        { session },
      );
      if (userIds.length) {
        await User.updateMany({ _id: { $in: userIds } }, { $set: { roleId: role._id } }, { session });
      }
      await writeAudit(req, "Role assignments updated", role.name, { userCount: userIds.length }, session);
    });
    res.json({ success: true, userIds });
  }),
);

api.get(
  "/users/all",
  asyncRoute(async (req, res) => {
    const users = await User.find().sort({ name: 1 }).lean();
    res.json({ success: true, users: await serializeUsers(users) });
  }),
);

api.get(
  "/users",
  asyncRoute(async (req, res) => {
    const users = await User.find({ isActive: true }).sort({ name: 1 }).lean();
    res.json({ success: true, users: await serializeUsers(users) });
  }),
);

api.post(
  "/users",
  checkOrigin,
  asyncRoute(async (req, res) => {
    const input = parseBody(createUserSchema, req);
    const normalizedEmail = input.email.trim().toLowerCase();
    const passwordHash = await bcrypt.hash(input.password, 12);
    const user = await inTransaction(async (session) => {
      const role = await Role.findById(input.roleId).session(session);
      if (!role) throw new HttpError(404, "Role not found.", "ROLE_NOT_FOUND");
      if (role.status !== "ACTIVE") {
        throw new HttpError(409, "Inactive roles cannot be assigned to users.", "ROLE_INACTIVE");
      }
      if (role.name === "System Administrator") {
        throw new HttpError(403, "New System Administrator accounts must use the protected setup flow.", "PROTECTED_ROLE");
      }

      const branch = await Branch.findOne({ _id: input.branchId, isActive: true }).session(session);
      if (!branch) throw new HttpError(400, "Select an active branch.", "INVALID_BRANCH");
      const existingUser = await User.exists({ normalizedEmail }).session(session);
      if (existingUser) {
        throw new HttpError(409, "An account with this email already exists.", "DUPLICATE_EMAIL");
      }

      const record = new User({
        name: input.name,
        email: normalizedEmail,
        normalizedEmail,
        passwordHash,
        roleId: role._id,
        branchId: branch._id,
        isActive: true,
      });
      await record.save({ session });
      await writeAudit(
        req,
        "User created",
        record.email,
        { roleId: role._id.toString(), branchId: branch._id },
        session,
      );
      return record;
    });
    res.status(201).json({ success: true, user: (await serializeUsers([user]))[0] });
  }),
);

api.patch(
  "/users/:id/role",
  checkOrigin,
  asyncRoute(async (req, res) => {
    const { roleId } = req.body || {};
    if (!roleId) {
      throw new HttpError(400, "Role ID is required.", "ROLE_REQUIRED");
    }
    const updatedUser = await inTransaction(async (session) => {
      const user = await User.findById(req.params.id).session(session);
      if (!user) throw new HttpError(404, "User not found.", "USER_NOT_FOUND");

      const newRole = await Role.findById(roleId).session(session);
      if (!newRole) throw new HttpError(404, "Role not found.", "ROLE_NOT_FOUND");
      if (newRole.status !== "ACTIVE") {
        throw new HttpError(409, "Inactive roles cannot be assigned to users.", "ROLE_INACTIVE");
      }

      const adminRole = await Role.findOne({ normalizedName: "system administrator" })
        .select("_id")
        .session(session);
      if (adminRole && newRole._id.toString() === adminRole._id.toString() && user.roleId?.toString() !== adminRole._id.toString()) {
        throw new HttpError(403, "Administrator accounts can only be created through the protected setup flow.", "PROTECTED_ROLE");
      }
      if (
        adminRole &&
        user.roleId?.toString() === adminRole._id.toString() &&
        newRole._id.toString() !== adminRole._id.toString()
      ) {
        await Role.updateOne({ _id: adminRole._id }, { $inc: { adminLockVersion: 1 } }, { session });
        const adminCount = await User.countDocuments({ roleId: adminRole._id, isActive: true }).session(session);
        if (adminCount <= 1) {
          throw new HttpError(409, "At least one active System Administrator account must remain.", "LAST_ADMINISTRATOR");
        }
      }

      user.roleId = newRole._id;
      await user.save({ session });
      await writeAudit(
        req,
        "User role updated",
        user.name,
        { roleId: newRole._id.toString(), roleName: newRole.name },
        session,
      );
      return user;
    });
    res.json({ success: true, user: (await serializeUsers([updatedUser]))[0] });
  }),
);

api.get(
  "/audit",
  asyncRoute(async (req, res) => {
    const events = await AuditLog.find().sort({ createdAt: -1 }).limit(200).lean();
    res.json({ success: true, events: events.map(serializeAudit) });
  }),
);

export default api;
