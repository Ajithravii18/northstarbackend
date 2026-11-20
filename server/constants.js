export const ACTIONS = ["VIEW", "CREATE", "EDIT", "DELETE", "APPROVE", "EXPORT"];

export const MODULES = [
  "DASHBOARD",
  "CUSTOMERS",
  "MEMBERSHIP",
  "SAVINGS",
  "RD",
  "LOAN",
  "CHITTY",
  "REPORTS",
];

export const BRANCHES = [
  { id: "kochi-main", name: "Kochi Main" },
  { id: "ernakulam", name: "Ernakulam" },
  { id: "thrissur", name: "Thrissur" },
  { id: "kozhikode", name: "Kozhikode" },
  { id: "trivandrum", name: "Trivandrum" },
];

export const BRANCH_SCOPES = ["ASSIGNED_BRANCH", "SELECTED_BRANCHES", "ALL_BRANCHES"];
export const ROLE_STATUSES = ["ACTIVE", "INACTIVE"];

export const ALL_PERMISSIONS = Object.fromEntries(
  MODULES.map((moduleName) => [moduleName, [...ACTIONS]]),
);

export const scopeToLabel = {
  ASSIGNED_BRANCH: "Assigned Branch",
  SELECTED_BRANCHES: "Selected Branches",
  ALL_BRANCHES: "All Branches",
};

export const scopeFromLabel = Object.fromEntries(
  Object.entries(scopeToLabel).map(([code, label]) => [label, code]),
);
