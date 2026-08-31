export const tenantRoles = ["admin", "operator"] as const;
export type TenantRole = (typeof tenantRoles)[number];

export const tenantAccessActions = [
  "access_audit.list",
  "asset.list",
  "credential.create",
  "credential.list",
  "credential.revoke",
  "device.list",
  "device.revoke",
  "device_audit.list",
  "enrollment_token.create",
  "entitlement.list",
  "entitlement.publish",
  "entitlement_revocations.publish",
  "incident_case.audit.list",
  "incident_case.close",
  "incident_case.create",
  "incident_case.link_work_order",
  "incident_case.list",
  "incident_case.update",
  "policy.list",
  "policy.publish",
  "policy_trust_anchor.set",
  "update.list",
  "update.publish",
  "work_order.approve",
  "work_order.cancel",
  "work_order.create",
  "work_order.list",
  "work_order_audit.list",
] as const;
export type TenantAccessAction = (typeof tenantAccessActions)[number];

export type TenantAccessOutcome = "allowed" | "denied";
export type TenantAccessTargetType =
  "credential" | "device" | "incident_case" | "tenant" | "work_order";

export function tenantRoleAllows(
  actual: TenantRole,
  required: TenantRole,
): boolean {
  return actual === "admin" || required === "operator";
}

export function isTenantRole(value: string): value is TenantRole {
  return (tenantRoles as readonly string[]).includes(value);
}

export function isTenantAccessAction(
  value: string,
): value is TenantAccessAction {
  return (tenantAccessActions as readonly string[]).includes(value);
}

export function validCredentialLabel(value: string): boolean {
  return (
    value.length >= 1 &&
    value.length <= 80 &&
    /^[A-Za-z0-9][A-Za-z0-9 ._@+-]*$/.test(value)
  );
}

export function validIncidentAssigneeLabel(value: string): boolean {
  return (
    value.length >= 1 &&
    value.length <= 64 &&
    /^[A-Za-z0-9][A-Za-z0-9 ._+-]*$/.test(value)
  );
}
