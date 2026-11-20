import { AuditLog, Branch, Role, User } from "./models.js";
import { ACTIONS, MODULES, scopeToLabel } from "./constants.js";

const actionToLabel = Object.fromEntries(
  ACTIONS.map((action) => [action, action[0] + action.slice(1).toLowerCase()]),
);

export function serializeRole(role, userIds = []) {
  return {
    id: role._id.toString(),
    name: role.name,
    description: role.description,
    status: role.status === "ACTIVE" ? "Active" : "Inactive",
    branchScope: scopeToLabel[role.branchScope],
    branchIds: [...role.branchIds],
    approvalLevel: role.approvalLevel,
    approvalLimit: role.approvalLimit ?? null,
    permissions: Object.fromEntries(
      MODULES.map((moduleName) => [
        actionToFrontendModule(moduleName),
        (role.permissions?.[moduleName] ?? []).map((action) => actionToLabel[action]),
      ]),
    ),
    userIds,
    createdAt: role.createdAt.toISOString(),
  };
}

function actionToFrontendModule(moduleName) {
  return moduleName === "RD"
    ? "RD"
    : moduleName.slice(0, 1) + moduleName.slice(1).toLowerCase();
}

export async function serializeRoles(roles) {
  if (roles.length === 0) return [];
  const ids = roles.map((role) => role._id);
  const assignedUsers = await User.find({ roleId: { $in: ids } }).select("_id roleId").lean();
  const userIdsByRole = new Map(roles.map((role) => [role._id.toString(), []]));
  for (const user of assignedUsers) {
    userIdsByRole.get(user.roleId.toString())?.push(user._id.toString());
  }
  return roles.map((role) => serializeRole(role, userIdsByRole.get(role._id.toString()) ?? []));
}

export async function serializeUsers(users) {
  if (!users.length) return [];
  const branchIds = [...new Set(users.map((user) => user.branchId).filter(Boolean))];
  const branches = await Branch.find({ _id: { $in: branchIds } }).lean();
  const branchNameById = new Map(branches.map((branch) => [branch._id, branch.name]));
  const roleIds = [...new Set(users.map((user) => user.roleId).filter(Boolean))];
  const roles = await Role.find({ _id: { $in: roleIds } }).select("name").lean();
  const roleNameById = new Map(roles.map((role) => [role._id.toString(), role.name]));

  return users.map((user) => ({
    id: user._id.toString(),
    name: user.name,
    email: user.email,
    branch: user.branchId ? branchNameById.get(user.branchId) ?? "Unassigned" : "Unassigned",
    branchId: user.branchId,
    roleId: user.roleId?.toString() ?? null,
    roleName: user.roleId ? roleNameById.get(user.roleId.toString()) ?? "Unassigned" : "Unassigned",
    isActive: user.isActive,
  }));
}

export function serializeAudit(event) {
  return {
    id: event._id.toString(),
    action: event.action,
    target: event.target,
    actor: event.actor,
    timestamp: event.createdAt.toISOString(),
  };
}

export async function writeAudit(req, action, target, metadata = {}, session) {
  const record = {
    action,
    target,
    actorId: req.user?._id ?? null,
    actor: req.user?.name ?? "System setup",
    metadata,
  };
  await AuditLog.create([record], session ? { session } : undefined);
}
