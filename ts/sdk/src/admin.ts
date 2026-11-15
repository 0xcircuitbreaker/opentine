/**
 * The 0.52 admin surface (tag `admin`, SPEC 8.27): session, login and tenant
 * management. None of it carries signed data, and the server never holds a
 * user signing key: a passkey's private key stays in the authenticator.
 *
 *   const admin = new TineAdmin(client);
 *   const options = await admin.passkeyAssertionOptions();
 *   // ... navigator.credentials.get(...) in the browser ...
 *   const session = await admin.passkeyLogin(assertion);
 */

import type { TineClient } from "./client.js";
import type {
  Hold,
  InvitationCreated,
  Invitation,
  Member,
  Oid,
  PasskeyAssertion,
  PasskeyOptions,
  PasskeyRegistered,
  PasskeyRegistration,
  Retention,
  RetentionPolicy,
  Role,
  Session,
  SessionOpened,
  Tenant,
  TenantSettings,
} from "./types.js";

type Settings = { description?: string | null; homepage?: string | null; default_ref?: string | null };

export class TineAdmin {
  constructor(readonly client: TineClient) {}

  private async json<T>(operation: Parameters<TineClient["send"]>[0], init: Parameters<TineClient["send"]>[1] = {}): Promise<T> {
    return (await (await this.client.send(operation, init)).json()) as T;
  }

  private tenant(tenant?: string): Record<string, string> {
    return { tenant: tenant ?? this.client.tenant };
  }

  /** Who is calling (a session or a bearer token) and the tenants they can see. */
  session(): Promise<Session> {
    return this.json("getSession");
  }

  /** Log out. False when the caller holds a bearer token rather than a session. */
  async logout(): Promise<boolean> {
    return (await this.json<{ ended: boolean }>("endSession")).ended;
  }

  /** `tine serve --insecure-dev --dev-login` only: a session with no proof at all. */
  devLogin(subject: string): Promise<SessionOpened> {
    return this.json("devLogin", { json: { subject }, anonymous: true });
  }

  /** Creation options for `navigator.credentials.create`; with no session, pass an invitation. */
  passkeyRegistrationOptions(invitation?: string): Promise<PasskeyOptions> {
    return this.json("passkeyRegistrationOptions", { json: invitation ? { invitation } : {}, anonymous: !!invitation });
  }

  registerPasskey(registration: PasskeyRegistration): Promise<PasskeyRegistered> {
    return this.json("registerPasskey", { json: registration, anonymous: !!registration.invitation });
  }

  passkeyAssertionOptions(): Promise<PasskeyOptions> {
    return this.json("passkeyAssertionOptions", { json: {}, anonymous: true });
  }

  passkeyLogin(assertion: PasskeyAssertion): Promise<SessionOpened> {
    return this.json("passkeyLogin", { json: assertion, anonymous: true });
  }

  async listTenants(): Promise<Tenant[]> {
    return (await this.json<{ tenants: Tenant[] }>("listTenants")).tenants;
  }

  createTenant(name: string, displayName?: string): Promise<Tenant> {
    return this.json("createTenant", { json: displayName ? { name, display_name: displayName } : { name } });
  }

  acceptInvitation(token: string): Promise<Tenant> {
    return this.json("acceptInvitation", { json: { token } });
  }

  getTenant(tenant?: string): Promise<Tenant> {
    return this.json("getTenant", { params: this.tenant(tenant) });
  }

  /** Change the display name; the tenant id in every URL never changes. */
  renameTenant(displayName: string, tenant?: string): Promise<Tenant> {
    return this.json("renameTenant", { params: this.tenant(tenant), json: { display_name: displayName } });
  }

  archiveTenant(tenant?: string): Promise<Tenant> {
    return this.json("archiveTenant", { params: this.tenant(tenant), json: {} });
  }

  unarchiveTenant(tenant?: string): Promise<Tenant> {
    return this.json("unarchiveTenant", { params: this.tenant(tenant), json: {} });
  }

  async listMembers(tenant?: string): Promise<Member[]> {
    return (await this.json<{ members: Member[] }>("listMembers", { params: this.tenant(tenant) })).members;
  }

  async setMember(subject: string, role: Role, tenant?: string): Promise<Member[]> {
    const params = { ...this.tenant(tenant), subject };
    return (await this.json<{ members: Member[] }>("setMember", { params, json: { role } })).members;
  }

  async removeMember(subject: string, tenant?: string): Promise<Member[]> {
    const params = { ...this.tenant(tenant), subject };
    return (await this.json<{ members: Member[] }>("removeMember", { params })).members;
  }

  async listInvitations(tenant?: string): Promise<Invitation[]> {
    return (await this.json<{ invitations: Invitation[] }>("listInvitations", { params: this.tenant(tenant) })).invitations;
  }

  createInvitation(role: Role = "reader", ttlSeconds?: number, tenant?: string): Promise<InvitationCreated> {
    const json = ttlSeconds === undefined ? { role } : { role, ttl_seconds: ttlSeconds };
    return this.json("createInvitation", { params: this.tenant(tenant), json });
  }

  async revokeInvitation(id: string, tenant?: string): Promise<void> {
    await this.client.send("revokeInvitation", { params: { ...this.tenant(tenant), invitation_id: id } });
  }

  getSettings(tenant?: string): Promise<TenantSettings> {
    return this.json("getSettings", { params: this.tenant(tenant) });
  }

  /** Merge settings; a null value removes that key. */
  updateSettings(settings: Settings, tenant?: string): Promise<TenantSettings> {
    return this.json("updateSettings", { params: this.tenant(tenant), json: settings });
  }

  getRetention(tenant?: string): Promise<Retention> {
    return this.json("getRetention", { params: this.tenant(tenant) });
  }

  setRetention(policy: RetentionPolicy, tenant?: string): Promise<Retention> {
    return this.json("setRetention", { params: this.tenant(tenant), json: policy });
  }

  async listHolds(tenant?: string): Promise<Hold[]> {
    return (await this.json<{ holds: Hold[] }>("listHolds", { params: this.tenant(tenant) })).holds;
  }

  async addHold(oid: Oid, tenant?: string): Promise<Hold[]> {
    return (await this.json<{ holds: Hold[] }>("addHold", { params: this.tenant(tenant), json: { oid } })).holds;
  }

  async releaseHold(oid: Oid, tenant?: string): Promise<Hold[]> {
    return (await this.json<{ holds: Hold[] }>("releaseHold", { params: { ...this.tenant(tenant), oid } })).holds;
  }
}
