import bcrypt from "bcryptjs";
import { randomBytes } from "node:crypto";
import { ALL_PERMISSIONS, BRANCHES, MODULES } from "./constants.js";
import { AuditLog, Branch, Role, User } from "./models.js";

const grant = (permissions) => ({
  ...Object.fromEntries(MODULES.map((moduleName) => [moduleName, []])),
  ...permissions,
});

const roleSeeds = [
  {
    name: "System Administrator",
    description: "Full access to every module and system configuration.",
    status: "ACTIVE",
    branchScope: "ALL_BRANCHES",
    branchIds: [],
    approvalLevel: 3,
    approvalLimit: null,
    permissions: ALL_PERMISSIONS,
  },
  {
    name: "Branch Manager",
    description: "Oversees daily operations and approvals for a branch.",
    status: "ACTIVE",
    branchScope: "ASSIGNED_BRANCH",
    branchIds: [],
    approvalLevel: 2,
    approvalLimit: 250000,
    permissions: grant({
      DASHBOARD: ["VIEW"],
      CUSTOMERS: ["VIEW", "CREATE", "EDIT", "EXPORT"],
      MEMBERSHIP: ["VIEW", "CREATE", "EDIT", "APPROVE", "EXPORT"],
      SAVINGS: ["VIEW", "CREATE", "EDIT", "APPROVE", "EXPORT"],
      RD: ["VIEW", "CREATE", "EDIT", "APPROVE"],
      LOAN: ["VIEW", "CREATE", "EDIT", "APPROVE", "EXPORT"],
      CHITTY: ["VIEW", "CREATE", "EDIT", "APPROVE"],
      REPORTS: ["VIEW", "EXPORT"],
    }),
  },
  {
    name: "Cashier",
    description: "Processes customer payments and day-to-day transactions.",
    status: "ACTIVE",
    branchScope: "ASSIGNED_BRANCH",
    branchIds: [],
    approvalLevel: 1,
    approvalLimit: 25000,
    permissions: grant({
      DASHBOARD: ["VIEW"],
      CUSTOMERS: ["VIEW"],
      MEMBERSHIP: ["VIEW"],
      SAVINGS: ["VIEW", "CREATE"],
      RD: ["VIEW", "CREATE"],
      CHITTY: ["VIEW", "CREATE"],
    }),
  },
  {
    name: "Accountant",
    description: "Reviews financial records, balances, and reporting.",
    status: "ACTIVE",
    branchScope: "SELECTED_BRANCHES",
    branchIds: ["kochi-main", "ernakulam"],
    approvalLevel: 2,
    approvalLimit: 100000,
    permissions: grant({
      DASHBOARD: ["VIEW"],
      SAVINGS: ["VIEW", "EDIT", "EXPORT"],
      RD: ["VIEW", "EXPORT"],
      LOAN: ["VIEW", "EXPORT"],
      REPORTS: ["VIEW", "EXPORT"],
    }),
  },
  {
    name: "Auditor",
    description: "Read-only access for compliance reviews and audit reporting.",
    status: "ACTIVE",
    branchScope: "ALL_BRANCHES",
    branchIds: [],
    approvalLevel: 0,
    approvalLimit: null,
    permissions: grant({
      DASHBOARD: ["VIEW"],
      CUSTOMERS: ["VIEW"],
      MEMBERSHIP: ["VIEW"],
      SAVINGS: ["VIEW"],
      RD: ["VIEW"],
      LOAN: ["VIEW"],
      CHITTY: ["VIEW"],
      REPORTS: ["VIEW", "EXPORT"],
    }),
  },
  {
    name: "Collection Officer",
    description: "Tracks collections and follows up on assigned accounts.",
    status: "ACTIVE",
    branchScope: "SELECTED_BRANCHES",
    branchIds: ["thrissur", "kozhikode"],
    approvalLevel: 0,
    approvalLimit: null,
    permissions: grant({
      DASHBOARD: ["VIEW"],
      CUSTOMERS: ["VIEW", "EDIT"],
      SAVINGS: ["VIEW", "CREATE"],
      LOAN: ["VIEW"],
    }),
  },
];

const userSeeds = [
  { name: "Anil Kumar", email: "admin@northstar.io", branchId: "kochi-main", role: "System Administrator" },
  { name: "Meera Nair", email: "meera.nair@northstar.io", branchId: "ernakulam", role: "Branch Manager" },
  { name: "Rahul S", email: "rahul.s@northstar.io", branchId: "kochi-main", role: "Cashier" },
  { name: "Sneha P", email: "sneha.p@northstar.io", branchId: "thrissur", role: "Accountant" },
  { name: "Joseph T", email: "joseph.t@northstar.io", branchId: "thrissur", role: "Collection Officer" },
  { name: "Fathima K", email: "fathima.k@northstar.io", branchId: "kozhikode", role: "Auditor" },
  { name: "Arun M", email: "arun.m@northstar.io", branchId: "trivandrum", role: "Cashier" },
  { name: "Divya R", email: "divya.r@northstar.io", branchId: "thrissur", role: "Branch Manager" },
];

export async function seedDevelopmentData() {
  await Branch.deleteMany({});
  for (const branch of BRANCHES) {
    await Branch.create({ _id: branch.id, name: branch.name, isActive: true });
  }

  const roleByName = new Map();
  for (const roleSeed of roleSeeds) {
    const role = await Role.findOneAndUpdate(
      { normalizedName: roleSeed.name.toLowerCase() },
      { $set: { ...roleSeed, normalizedName: roleSeed.name.toLowerCase() } },
      { upsert: true, new: true },
    );
    roleByName.set(role.name, role);
  }

  await User.deleteMany({});
  const developmentPassword = process.env.DEMO_ADMIN_PASSWORD || randomBytes(24).toString("base64url");
  const adminPasswordHash = await bcrypt.hash(developmentPassword, 12);
  console.info(`Development-only shared mock-user password: ${developmentPassword}`);

  for (const userSeed of userSeeds) {
    const role = roleByName.get(userSeed.role);
    await User.create({
      name: userSeed.name,
      email: userSeed.email,
      normalizedEmail: userSeed.email.toLowerCase(),
      branchId: userSeed.branchId,
      roleId: role ? role._id : null,
      passwordHash: adminPasswordHash,
      isActive: true,
    });
  }

  if (!(await AuditLog.exists({ target: "Branch Manager" }))) {
    await AuditLog.create({
      action: "Role created",
      target: "Branch Manager",
      actor: "Development seed",
      metadata: {},
    });
  }

  console.info(`Development data ready: ${roleSeeds.length} roles, ${userSeeds.length} mock users.`);
}
