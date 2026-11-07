import { createFileRoute } from "@tanstack/react-router";

async function handle(request: Request) {
  const { handler } = await import("@/shopflow/backend/index");
  const url = new URL(request.url);
  const headers: Record<string, string> = {};
  request.headers.forEach((v, k) => (headers[k.toLowerCase()] = v));
  if (!headers["x-forwarded-host"]) headers["x-forwarded-host"] = url.host;
  if (!headers["x-forwarded-proto"]) headers["x-forwarded-proto"] = url.protocol.replace(":", "");
  const query: Record<string, string> = {};
  url.searchParams.forEach((v, k) => (query[k] = v));
  const body = request.method === "GET" || request.method === "HEAD" ? "" : await request.text();
  const event = {
    httpMethod: request.method,
    path: url.pathname,
    rawPath: url.pathname,
    headers,
    queryStringParameters: query,
    body,
    isBase64Encoded: false,
    requestContext: { requestId: crypto.randomUUID(), domainName: url.host, http: { method: request.method, path: url.pathname, sourceIp: headers["cf-connecting-ip"] || headers["x-forwarded-for"] || "" } },
  };
  const out: any = await handler(event);
  const resHeaders = new Headers();
  for (const [k, v] of Object.entries(out?.headers || {})) if (v != null) resHeaders.set(k, String(v));
  const status = Number(out?.statusCode) || 200;
  const resBody = status === 204 ? null : out?.isBase64Encoded ? Uint8Array.from(atob(out.body || ""), (c) => c.charCodeAt(0)) : (out?.body ?? "");
  return new Response(resBody, { status, headers: resHeaders });
}

export const Route = createFileRoute("/api/$")({
  server: {
    handlers: {
      GET: ({ request }) => handle(request),
      POST: ({ request }) => handle(request),
      PUT: ({ request }) => handle(request),
      PATCH: ({ request }) => handle(request),
      DELETE: ({ request }) => handle(request),
      OPTIONS: ({ request }) => handle(request),
    },
  },
});
