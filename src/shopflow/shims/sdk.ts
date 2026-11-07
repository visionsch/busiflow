// Server-side replacement for the original @appdeploy/sdk, backed by the connected Supabase project.
// Records live in public.app_records (table_name, id, data jsonb); atomic writes go through public.app_transact.
import { supabaseAdmin } from "@/integrations/supabase/client.server";

const BUCKET = "app-files";
const sb = () => supabaseAdmin as any;

export class AppDatabaseError extends Error {
  code: string;
  constructor(code: string, message?: string) {
    super(message || code);
    this.code = code;
  }
}
export function isAppDatabaseError(e: unknown): e is AppDatabaseError {
  return e instanceof AppDatabaseError;
}

function fail(error: any): never {
  const msg = String(error?.message || "");
  if (msg.includes("AppDatabaseConditionFailed")) throw new AppDatabaseError("AppDatabaseConditionFailed");
  if (msg.includes("AppDatabaseConflict")) throw new AppDatabaseError("AppDatabaseConflict");
  throw new AppDatabaseError("AppDatabaseGatewayUnavailable", msg);
}

type Op = { op: "add" | "update" | "delete"; table: string; items: unknown[] };
const clean = (v: unknown) => JSON.parse(JSON.stringify(v ?? null));

async function transact(ops: Op[]): Promise<any[][]> {
  const { data, error } = await sb().rpc("app_transact", { ops: clean(ops) });
  if (error) fail(error);
  return data as any[][];
}

export const db = {
  async get<T = any>(table: string, ids: string[], _opts?: unknown): Promise<(T & { id: string } | null)[]> {
    const wanted = ids.map(String);
    if (!wanted.length) return [];
    const { data, error } = await sb().from("app_records").select("id,data").eq("table_name", table).in("id", wanted);
    if (error) fail(error);
    const map = new Map<string, any>((data || []).map((r: any) => [r.id, { ...r.data, id: r.id }]));
    return wanted.map((id) => map.get(id) ?? null);
  },
  async list<T = any>(table: string, opts: { limit?: number; nextToken?: string } = {}) {
    const limit = Math.max(1, Math.min(Number(opts.limit) || 100, 1000));
    const offset = Number(opts.nextToken || 0) || 0;
    const { data, error } = await sb()
      .from("app_records").select("id,data").eq("table_name", table)
      .order("created_at", { ascending: true }).order("id", { ascending: true })
      .range(offset, offset + limit);
    if (error) fail(error);
    const rows = data || [];
    const items = rows.slice(0, limit).map((r: any) => ({ ...r.data, id: r.id })) as (T & { id: string })[];
    return { items, nextToken: rows.length > limit ? String(offset + limit) : undefined };
  },
  async add(table: string, records: Record<string, unknown>[]) {
    return (await transact([{ op: "add", table, items: records }]))[0] as string[];
  },
  async update(table: string, items: { id: string; record: Record<string, unknown>; if?: Record<string, unknown> }[]) {
    return (await transact([{ op: "update", table, items }]))[0] as boolean[];
  },
  async delete(table: string, ids: string[]) {
    return (await transact([{ op: "delete", table, items: ids }]))[0] as boolean[];
  },
  async transact(ops: Op[]) {
    return transact(ops);
  },
  tx: {
    add: (table: string, items: unknown[]): Op => ({ op: "add", table, items }),
    update: (table: string, items: unknown[]): Op => ({ op: "update", table, items }),
    delete: (table: string, items: unknown[]): Op => ({ op: "delete", table, items }),
  },
};

export const secrets = {
  async listSecretNames(): Promise<string[]> {
    return Object.keys(process.env).filter((k) => !!process.env[k]);
  },
  async readSecret(name: string): Promise<string> {
    const v = process.env[name];
    if (!v) throw new Error("secret_not_configured: " + name);
    return v;
  },
};

function toBytes(content: unknown): Uint8Array {
  if (content instanceof Uint8Array) return content;
  if (content instanceof ArrayBuffer) return new Uint8Array(content);
  let s = String(content ?? "");
  const i = s.indexOf("base64,");
  if (i >= 0) s = s.slice(i + 7);
  const bin = atob(s.replace(/\s/g, ""));
  const out = new Uint8Array(bin.length);
  for (let j = 0; j < bin.length; j++) out[j] = bin.charCodeAt(j);
  return out;
}

export const storage = {
  async write(files: { path: string; content: unknown; contentType?: string }[]) {
    return Promise.all(files.map(async (f) => {
      try {
        const { error } = await sb().storage.from(BUCKET).upload(f.path, toBytes(f.content), { contentType: f.contentType, upsert: true });
        return !error;
      } catch { return false; }
    }));
  },
  async url(paths: string[]) {
    return Promise.all(paths.map(async (path) => {
      const { data } = await sb().storage.from(BUCKET).createSignedUrl(path, 60 * 60 * 24 * 7);
      return data?.signedUrl ? { path, url: data.signedUrl as string } : null;
    }));
  },
  async delete(paths: string[]) {
    if (!paths.length) return [];
    const { error } = await sb().storage.from(BUCKET).remove(paths);
    return paths.map(() => !error);
  },
};

export function json(data: unknown, statusCode = 200) {
  return { statusCode, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" }, body: JSON.stringify(data) };
}
export function error(message: string, statusCode = 400) {
  return json({ error: message }, statusCode);
}

type Handler = (ctx: { body: any; event: any }) => any;
export function router(routes: Record<string, Handler[]>) {
  return async (event: any) => {
    const method = String(event?.httpMethod || "").toUpperCase();
    const path = String(event?.path || "").split("?")[0];
    const chain = routes[method + " " + path];
    if (!chain) return error("Not found.", 404);
    let body: any = undefined;
    if (typeof event?.body === "string" && event.body) {
      try { body = JSON.parse(event.body); } catch { body = {}; }
    } else if (event?.body && typeof event.body === "object") body = event.body;
    const ctx = { body: body ?? {}, event };
    let result: any;
    for (const h of chain) {
      result = await h(ctx);
      if (result) return result;
    }
    return result ?? error("No response.", 500);
  };
}

export const ws = { async send(_connectionId: string, _data: unknown) { return false; } };
