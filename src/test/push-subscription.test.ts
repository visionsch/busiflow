import { webcrypto } from "node:crypto";
import { beforeEach, describe, expect, it, vi } from "vitest";

const store = vi.hoisted(() => new Map<string, Record<string, unknown>>());
const add = vi.hoisted(() => vi.fn(async (table: string, rows: Record<string, unknown>[]) => {
  for (const row of rows) store.set(`${table}/${row['id']}`, { ...row });
  return rows.map(row => row['id']);
}));

vi.mock("@/shopflow/shims/sdk", () => ({
  db: {
    get: async (table: string, ids: string[]) => ids.map(id => store.get(`${table}/${id}`) ?? null),
    add,
    update: async (table: string, rows: { id: string; record: Record<string, unknown> }[]) => rows.map(row => {
      store.set(`${table}/${row.id}`, { ...row.record });
      return true;
    }),
    tx: { add: (table: string, items: unknown[]) => ({ op: "add", table, items }) },
  },
  secrets: { readSecret: async () => "test-only-encryption-key-for-notifications" },
  storage: {},
  isAppDatabaseError: () => false,
  json: (value: unknown) => ({ statusCode: 200, body: JSON.stringify(value) }),
  router: (routes: Record<string, ((ctx: unknown) => unknown)[]>) => async (event: { httpMethod: string; path: string; body?: string }) => {
    const handlers = routes[`${event.httpMethod} ${event.path}`];
    for (const handle of handlers ?? []) {
      const result = await handle({ event, body: JSON.parse(event.body || "{}") });
      if (result) return result;
    }
    return undefined;
  },
}));

import { handler } from "@/shopflow/backend/index";

function subscribe(subscription: unknown, csrf = "test-csrf") {
  return handler({
    httpMethod: "POST", path: "/api/push/subscribe",
    headers: { cookie: "shopflow_session=test-session", "x-csrf-token": csrf, "content-type": "application/json" },
    body: JSON.stringify({ subscription }),
  });
}

describe("Push subscription persistence", () => {
  beforeEach(() => {
    vi.stubGlobal("crypto", webcrypto);
    store.clear();
    add.mockClear();
    store.set("sessions/test-session", { userId: "test-user", csrfToken: "test-csrf", expiresAt: Date.now() + 60000 });
    store.set("users/test-user", { id: "test-user", role: "Super Admin", ownerId: "test-user", active: true });
  });

  it("saves a new authenticated subscription before reporting success", async () => {
    const subscription = { endpoint: "https://push.example.test/subscription", keys: { p256dh: "public-key", auth: "auth-key" } };
    const response = await subscribe(subscription);
    expect(response.statusCode).toBe(200);
    const saved = [...store.entries()].filter(([key]) => key.startsWith("push_subscriptions/"));
    expect(saved).toHaveLength(1);
    expect(saved[0]?.[1]).toMatchObject({ ...subscription, userId: "test-user", ownerId: "test-user" });
    expect(add).toHaveBeenCalledOnce();
  });

  it("updates an existing subscription without adding a duplicate", async () => {
    const subscription = { endpoint: "https://push.example.test/subscription", keys: { p256dh: "public-key", auth: "old-auth" } };
    await subscribe(subscription);
    const response = await subscribe({ ...subscription, keys: { ...subscription.keys, auth: "new-auth" } });
    expect(response.statusCode).toBe(200);
    const saved = [...store.entries()].filter(([key]) => key.startsWith("push_subscriptions/"));
    expect(saved).toHaveLength(1);
    expect(saved[0]?.[1]['keys']).toEqual({ p256dh: "public-key", auth: "new-auth" });
    expect(add).toHaveBeenCalledOnce();
  });

  it("does not persist a subscription with an invalid CSRF token", async () => {
    const response = await subscribe({ endpoint: "https://push.example.test/subscription", keys: { p256dh: "key", auth: "auth" } }, "wrong-csrf");
    expect(response.statusCode).toBe(403);
    expect(add).not.toHaveBeenCalled();
  });

  it("persists VAPID keys so later requests reuse the same public key", async () => {
    const request = { httpMethod: "GET", path: "/api/push/vapid-public-key", headers: { cookie: "shopflow_session=test-session" } };
    const first = await handler(request);
    const second = await handler(request);
    expect(first.statusCode).toBe(200);
    expect(second.statusCode).toBe(200);
    expect(JSON.parse(second.body).publicKey).toBe(JSON.parse(first.body).publicKey);
    expect(store.has("integration_secrets/shopflow_vapid_keys_v1")).toBe(true);
    expect(add).toHaveBeenCalledOnce();
  });
});