import mongoose from "mongoose";
import { ACTIONS, BRANCH_SCOPES, MODULES, ROLE_STATUSES } from "./constants.js";

const permissionFields = Object.fromEntries(
  MODULES.map((moduleName) => [
    moduleName,
    { type: [{ type: String, enum: ACTIONS }], default: [] },
  ]),
);

const permissionSchema = new mongoose.Schema(permissionFields, { _id: false });

const roleSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true, maxlength: 100 },
    normalizedName: { type: String, required: true, unique: true, index: true },
    description: { type: String, trim: true, maxlength: 500, default: "" },
    status: { type: String, enum: ROLE_STATUSES, default: "ACTIVE", required: true },
    branchScope: { type: String, enum: BRANCH_SCOPES, required: true },
    branchIds: { type: [String], default: [] },
    approvalLevel: { type: Number, min: 0, max: 100, default: 0 },
    approvalLimit: { type: Number, min: 0, default: null },
    adminLockVersion: { type: Number, default: 0, select: false },
    permissions: { type: permissionSchema, default: () => ({}) },
  },
  { timestamps: true, versionKey: false },
);

roleSchema.pre("validate", function normalizeRoleName() {
  if (this.name) this.normalizedName = this.name.trim().toLocaleLowerCase("en-US");
});

const userSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true, maxlength: 120 },
    email: { type: String, required: true, trim: true, lowercase: true, maxlength: 254 },
    normalizedEmail: { type: String, required: true, unique: true, index: true },
    passwordHash: { type: String, select: false },
    sessionVersion: { type: Number, default: 0 },
    passwordResetTokenHash: { type: String, select: false, index: true },
    passwordResetExpiresAt: { type: Date, select: false },
    roleId: { type: mongoose.Schema.Types.ObjectId, ref: "Role", default: null, index: true },
    branchId: { type: String, default: null, index: true },
    isActive: { type: Boolean, default: true },
  },
  { timestamps: true, versionKey: false },
);

userSchema.pre("validate", function normalizeEmail() {
  if (this.email) {
    this.email = this.email.trim().toLowerCase();
    this.normalizedEmail = this.email;
  }
});

const branchSchema = new mongoose.Schema(
  {
    _id: { type: String, required: true },
    name: { type: String, required: true, trim: true, unique: true },
    isActive: { type: Boolean, default: true },
  },
  { timestamps: true, versionKey: false },
);

const auditSchema = new mongoose.Schema(
  {
    action: { type: String, required: true, maxlength: 100 },
    target: { type: String, required: true, maxlength: 160 },
    actorId: { type: mongoose.Schema.Types.ObjectId, ref: "User", default: null },
    actor: { type: String, required: true, maxlength: 120 },
    metadata: { type: mongoose.Schema.Types.Mixed, default: {} },
  },
  { timestamps: true, versionKey: false },
);

export const Role = mongoose.models.Role || mongoose.model("Role", roleSchema);
export const User = mongoose.models.User || mongoose.model("User", userSchema);
export const Branch = mongoose.models.Branch || mongoose.model("Branch", branchSchema);
export const AuditLog = mongoose.models.AuditLog || mongoose.model("AuditLog", auditSchema);
