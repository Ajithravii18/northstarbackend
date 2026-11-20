import { z } from "zod";
import { ACTIONS, BRANCH_SCOPES, MODULES, ROLE_STATUSES } from "./constants.js";

const permissionsShape = Object.fromEntries(
  MODULES.map((moduleName) => [
    moduleName,
    z.array(z.enum(ACTIONS)).max(ACTIONS.length).default([]),
  ]),
);

export const permissionsSchema = z.object(permissionsShape).strict();

export const roleSchema = z
  .object({
    name: z.string().trim().min(1).max(100),
    description: z.string().trim().max(500).default(""),
    status: z.enum(ROLE_STATUSES),
    branchScope: z.enum(BRANCH_SCOPES),
    branchIds: z.array(z.string().trim().min(1).max(100)).max(100).default([]),
    approvalLevel: z.number().int().min(0).max(100),
    approvalLimit: z.number().finite().min(0).nullable(),
    permissions: permissionsSchema,
  })
  .strict();

export const permissionsUpdateSchema = z
  .object({ permissions: permissionsSchema })
  .strict();

export const statusUpdateSchema = z
  .object({ status: z.enum(ROLE_STATUSES) })
  .strict();

export const cloneSchema = z
  .object({ name: z.string().trim().min(1).max(100) })
  .strict();

export const assignmentSchema = z
  .object({ userIds: z.array(z.string().min(1).max(100)).max(1000) })
  .strict();

export const createUserSchema = z
  .object({
    name: z.string().trim().min(1).max(120),
    email: z.string().trim().email().max(254),
    password: z.string().min(12).max(128),
    roleId: z.string().regex(/^[a-f0-9]{24}$/i),
    branchId: z.string().trim().min(1).max(100),
  })
  .strict();

export const loginSchema = z
  .object({
    email: z.string().trim().email().max(254),
    password: z.string().min(1).max(128),
  })
  .strict();

export const forgotPasswordSchema = z
  .object({
    email: z.string().trim().email().max(254),
  })
  .strict();

export const resetPasswordSchema = z
  .object({
    token: z.string().regex(/^[a-f0-9]{64}$/),
    password: z.string().min(12).max(128),
    confirmPassword: z.string().min(12).max(128),
  })
  .strict()
  .refine((value) => value.password === value.confirmPassword, {
    message: "Passwords do not match.",
    path: ["confirmPassword"],
  });

export const setupSchema = z
  .object({
    token: z.string().min(32).max(512),
    name: z.string().trim().min(1).max(120),
    email: z.string().trim().email().max(254),
    password: z.string().min(12).max(128),
  })
  .strict();
