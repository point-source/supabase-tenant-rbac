import { createAddMemberHandler, type AddMemberRpc } from "./index.ts";

const BASE_URL = "http://localhost/functions/v1/add-member";

function makeHandler(
  rpcOverride?: AddMemberRpc,
  authorizeOverride?: (req: Request) => boolean | Promise<boolean>,
) {
  return createAddMemberHandler({
    supabaseUrl: "http://localhost:54321",
    serviceRoleKey: "service-role-key",
    addMemberRpc: rpcOverride ?? (async () => ({ data: "new-member-uuid", error: null })),
    authorizeRequest: authorizeOverride ?? (() => true),
  });
}

function post(body?: unknown, headers?: Record<string, string>) {
  return new Request(BASE_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...headers },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
}

// -- Config errors --

Deno.test("returns 500 when env config is missing", async () => {
  const handler = createAddMemberHandler({
    supabaseUrl: null,
    serviceRoleKey: null,
  });
  const res = await handler(post({ group_id: "g", user_id: "u", roles: ["r"] }));
  if (res.status !== 500) throw new Error(`Expected 500, got ${res.status}`);
});

// -- Method check --

Deno.test("returns 405 for non-POST methods", async () => {
  const handler = makeHandler();
  const req = new Request(BASE_URL, { method: "GET" });
  const res = await handler(req);
  if (res.status !== 405) throw new Error(`Expected 405, got ${res.status}`);
});

// -- Authorization --

Deno.test("returns 401 when authorizeRequest returns false", async () => {
  const handler = makeHandler(undefined, () => false);
  const res = await handler(post({ group_id: "g", user_id: "u", roles: ["r"] }));
  if (res.status !== 401) throw new Error(`Expected 401, got ${res.status}`);
});

Deno.test("returns 401 by default when bearer token is missing", async () => {
  const handler = createAddMemberHandler({
    supabaseUrl: "http://localhost:54321",
    serviceRoleKey: "service-role-key",
    addMemberRpc: async () => ({ data: "new-member-uuid", error: null }),
    getUserByToken: async () => ({
      user: { app_metadata: { roles: ["rbac_admin"] } },
      error: null,
    }),
  });
  const res = await handler(post({ group_id: "g", user_id: "u", roles: ["r"] }));
  if (res.status !== 401) throw new Error(`Expected 401, got ${res.status}`);
});

Deno.test("default auth allows super admin user", async () => {
  const handler = createAddMemberHandler({
    supabaseUrl: "http://localhost:54321",
    serviceRoleKey: "service-role-key",
    addMemberRpc: async () => ({ data: "new-member-uuid", error: null }),
    getUserByToken: async () => ({
      user: { app_metadata: { is_super_admin: true } },
      error: null,
    }),
  });
  const res = await handler(
    post(
      { group_id: "g", user_id: "u", roles: ["r"] },
      { Authorization: "Bearer token-123" },
    ),
  );
  if (res.status !== 201) throw new Error(`Expected 201, got ${res.status}`);
});

Deno.test("default auth allows configured app role", async () => {
  const handler = createAddMemberHandler({
    supabaseUrl: "http://localhost:54321",
    serviceRoleKey: "service-role-key",
    addMemberRpc: async () => ({ data: "new-member-uuid", error: null }),
    allowedAppRoles: ["tenant_admin", "rbac_admin"],
    getUserByToken: async () => ({
      user: { app_metadata: { roles: ["viewer", "tenant_admin"] } },
      error: null,
    }),
  });
  const res = await handler(
    post(
      { group_id: "g", user_id: "u", roles: ["r"] },
      { Authorization: "Bearer token-123" },
    ),
  );
  if (res.status !== 201) throw new Error(`Expected 201, got ${res.status}`);
});

Deno.test("default auth denies app role when allowed roles are not configured", async () => {
  const handler = createAddMemberHandler({
    supabaseUrl: "http://localhost:54321",
    serviceRoleKey: "service-role-key",
    addMemberRpc: async () => ({ data: "new-member-uuid", error: null }),
    getUserByToken: async () => ({
      user: { app_metadata: { roles: ["rbac_admin"] } },
      error: null,
    }),
  });
  const res = await handler(
    post(
      { group_id: "g", user_id: "u", roles: ["r"] },
      { Authorization: "Bearer token-123" },
    ),
  );
  if (res.status !== 401) throw new Error(`Expected 401, got ${res.status}`);
});

Deno.test("default auth denies user without admin role", async () => {
  const handler = createAddMemberHandler({
    supabaseUrl: "http://localhost:54321",
    serviceRoleKey: "service-role-key",
    addMemberRpc: async () => ({ data: "new-member-uuid", error: null }),
    allowedAppRoles: ["tenant_admin"],
    getUserByToken: async () => ({
      user: { app_metadata: { roles: ["viewer"] } },
      error: null,
    }),
  });
  const res = await handler(
    post(
      { group_id: "g", user_id: "u", roles: ["r"] },
      { Authorization: "Bearer token-123" },
    ),
  );
  if (res.status !== 401) throw new Error(`Expected 401, got ${res.status}`);
});

Deno.test("proceeds when authorizeRequest returns true", async () => {
  const handler = makeHandler(undefined, () => true);
  const res = await handler(post({ group_id: "g", user_id: "u", roles: ["editor"] }));
  if (res.status !== 201) throw new Error(`Expected 201, got ${res.status}`);
});

// -- Input validation --

Deno.test("returns 400 for missing body", async () => {
  const handler = makeHandler();
  const req = new Request(BASE_URL, { method: "POST" });
  const res = await handler(req);
  if (res.status !== 400) throw new Error(`Expected 400, got ${res.status}`);
});

Deno.test("returns 400 for empty JSON object", async () => {
  const handler = makeHandler();
  const res = await handler(post({}));
  if (res.status !== 400) throw new Error(`Expected 400, got ${res.status}`);
});

Deno.test("returns 400 when group_id is missing", async () => {
  const handler = makeHandler();
  const res = await handler(post({ user_id: "u", roles: ["editor"] }));
  if (res.status !== 400) throw new Error(`Expected 400, got ${res.status}`);
});

Deno.test("returns 400 when user_id is missing", async () => {
  const handler = makeHandler();
  const res = await handler(post({ group_id: "g", roles: ["editor"] }));
  if (res.status !== 400) throw new Error(`Expected 400, got ${res.status}`);
});

Deno.test("returns 400 when roles is missing", async () => {
  const handler = makeHandler();
  const res = await handler(post({ group_id: "g", user_id: "u" }));
  if (res.status !== 400) throw new Error(`Expected 400, got ${res.status}`);
});

Deno.test("returns 400 when roles is empty array", async () => {
  const handler = makeHandler();
  const res = await handler(post({ group_id: "g", user_id: "u", roles: [] }));
  if (res.status !== 400) throw new Error(`Expected 400, got ${res.status}`);
});

Deno.test("returns 400 when roles contains non-strings", async () => {
  const handler = makeHandler();
  const res = await handler(post({ group_id: "g", user_id: "u", roles: [123] }));
  if (res.status !== 400) throw new Error(`Expected 400, got ${res.status}`);
});

Deno.test("returns 400 when group_id is not a string", async () => {
  const handler = makeHandler();
  const res = await handler(post({ group_id: 123, user_id: "u", roles: ["editor"] }));
  if (res.status !== 400) throw new Error(`Expected 400, got ${res.status}`);
});

// -- Success path --

Deno.test("returns 201 with member_id on success", async () => {
  const handler = makeHandler(
    async () => ({ data: "returned-uuid", error: null }),
  );
  const res = await handler(
    post({ group_id: "g-id", user_id: "u-id", roles: ["editor"] }),
  );
  if (res.status !== 201) throw new Error(`Expected 201, got ${res.status}`);
  const body = await res.json();
  if (body.member_id !== "returned-uuid") {
    throw new Error(`Expected returned-uuid, got ${body.member_id}`);
  }
});

Deno.test("passes correct arguments to addMemberRpc", async () => {
  let capturedGroupId = "";
  let capturedUserId = "";
  let capturedRoles: string[] = [];

  const handler = makeHandler(async (groupId: string, userId: string, roles: string[]) => {
    capturedGroupId = groupId;
    capturedUserId = userId;
    capturedRoles = roles;
    return { data: "id", error: null };
  });

  await handler(
    post({
      group_id: "my-group",
      user_id: "my-user",
      roles: ["admin", "editor"],
    }),
  );

  if (capturedGroupId !== "my-group") {
    throw new Error(`Expected my-group, got ${capturedGroupId}`);
  }
  if (capturedUserId !== "my-user") {
    throw new Error(`Expected my-user, got ${capturedUserId}`);
  }
  if (capturedRoles.length !== 2 || capturedRoles[0] !== "admin" || capturedRoles[1] !== "editor") {
    throw new Error(`Expected [admin, editor], got ${JSON.stringify(capturedRoles)}`);
  }
});

// -- RPC error path --

Deno.test("returns 400 with error message when RPC fails", async () => {
  const handler = makeHandler(
    async () => ({ data: null, error: { message: "Role not found" } }),
  );
  const res = await handler(
    post({ group_id: "g", user_id: "u", roles: ["nonexistent"] }),
  );
  if (res.status !== 400) throw new Error(`Expected 400, got ${res.status}`);
  const body = await res.json();
  if (body.error !== "Role not found") {
    throw new Error(`Expected 'Role not found', got ${body.error}`);
  }
});

Deno.test("returns application/json content-type on error", async () => {
  const handler = makeHandler(
    async () => ({ data: null, error: { message: "fail", code: "XX000" } }),
  );
  const res = await handler(
    post({ group_id: "g", user_id: "u", roles: ["r"] }),
  );
  if (res.status !== 500) throw new Error(`Expected 500, got ${res.status}`);
  const ct = res.headers.get("Content-Type");
  if (ct !== "application/json") {
    throw new Error(`Expected application/json, got ${ct}`);
  }
});

Deno.test("maps permission errors to 403", async () => {
  const handler = makeHandler(
    async () => ({ data: null, error: { message: "permission denied", code: "42501" } }),
  );
  const res = await handler(post({ group_id: "g", user_id: "u", roles: ["r"] }));
  if (res.status !== 403) throw new Error(`Expected 403, got ${res.status}`);
});
