import { createInviteHandler } from "./index.ts";

Deno.test("invite handler returns 500 when env config is missing", async () => {
  const handler = createInviteHandler({ supabaseUrl: null, supabaseAnonKey: null });
  const req = new Request("http://localhost/functions/v1/invite", { method: "POST" });
  const res = await handler(req);
  if (res.status !== 500) {
    throw new Error(`Expected 500, got ${res.status}`);
  }
});

Deno.test("invite handler returns 401 for missing bearer token", async () => {
  const handler = createInviteHandler({
    supabaseUrl: "http://localhost:54321",
    supabaseAnonKey: "anon",
    inviteRpc: async () => ({ error: null }),
  });
  const req = new Request("http://localhost/functions/v1/invite", { method: "POST" });
  const res = await handler(req);
  if (res.status !== 401) {
    throw new Error(`Expected 401, got ${res.status}`);
  }
});

Deno.test("invite handler returns 400 for missing invite_code body", async () => {
  const handler = createInviteHandler({
    supabaseUrl: "http://localhost:54321",
    supabaseAnonKey: "anon",
    inviteRpc: async () => ({ error: null }),
  });
  const req = new Request("http://localhost/functions/v1/invite", {
    method: "POST",
    headers: { Authorization: "Bearer token", "Content-Type": "application/json" },
    body: JSON.stringify({}),
  });
  const res = await handler(req);
  if (res.status !== 400) {
    throw new Error(`Expected 400, got ${res.status}`);
  }
});

Deno.test("invite handler returns 201 and trims invite_code on success", async () => {
  let called = false;
  let passedToken = "";
  let passedInvite = "";
  const handler = createInviteHandler({
    supabaseUrl: "http://localhost:54321",
    supabaseAnonKey: "anon",
    inviteRpc: async (token, inviteCode) => {
      called = true;
      passedToken = token;
      passedInvite = inviteCode.trim();
      return { error: null };
    },
  });
  const req = new Request("http://localhost/functions/v1/invite", {
    method: "POST",
    headers: { Authorization: "Bearer token-123", "Content-Type": "application/json" },
    body: JSON.stringify({ invite_code: "  abc-uuid  " }),
  });
  const res = await handler(req);
  if (res.status !== 201) {
    throw new Error(`Expected 201, got ${res.status}`);
  }
  if (!called) {
    throw new Error("Expected RPC to be called");
  }
  if (passedToken !== "token-123") {
    throw new Error(`Expected token-123, got ${passedToken}`);
  }
  if (passedInvite !== "abc-uuid") {
    throw new Error(`Expected trimmed invite code abc-uuid, got ${passedInvite}`);
  }
});

Deno.test("invite handler returns 400 when RPC returns error", async () => {
  const handler = createInviteHandler({
    supabaseUrl: "http://localhost:54321",
    supabaseAnonKey: "anon",
    inviteRpc: async () => ({ error: { message: "boom" } }),
  });
  const req = new Request("http://localhost/functions/v1/invite", {
    method: "POST",
    headers: { Authorization: "Bearer token", "Content-Type": "application/json" },
    body: JSON.stringify({ invite_code: "id" }),
  });
  const res = await handler(req);
  if (res.status !== 400) {
    throw new Error(`Expected 400, got ${res.status}`);
  }
});
