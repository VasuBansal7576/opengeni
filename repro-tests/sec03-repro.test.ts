// SEC-03 reproduction (vulnerable baseline): an organization service key must
// NOT be able to mint or consume human-approval capabilities. On the
// vulnerable build these calls succeed; on the fixed build they are denied
// with 403 "canonical human session required for tool approval".
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { ToolGatewayApprovalResponse, ToolGatewayCatalog } from "@opengeni/contracts";
import {
  bootstrapWorkspace,
  createDb,
  createOrganizationApiKey,
  type DbClient,
} from "@opengeni/db";
import {
  acquireSharedTestDatabase,
  MemoryEventBus,
  startTestMcpServer,
  testSettings,
  type SharedTestDatabase,
  type TestMcpServer,
} from "@opengeni/testing";
import { createApp } from "../src/app";

let shared: SharedTestDatabase;
let client: DbClient;
let mcp: TestMcpServer;
let serviceApp: ReturnType<typeof createApp>;
let workspaceId: string;
let serviceHeaders: Record<string, string>;
let catalog: ToolGatewayCatalog;

beforeAll(async () => {
  const acquired = await acquireSharedTestDatabase("sec03-repro");
  if (!acquired) throw new Error("SEC-03 repro requires real PostgreSQL");
  shared = acquired;
  client = createDb(shared.appUrl);
  mcp = startTestMcpServer();
  const access = await bootstrapWorkspace(client.db, {
    accountExternalSource: "opengeni:local",
    accountExternalId: "default",
    accountName: "Local",
    workspaceExternalSource: "opengeni:local",
    workspaceExternalId: "default",
    workspaceName: "Local",
    subjectId: "dev",
    subjectLabel: "Local dev",
  });
  const grant = access.workspaceGrants[0];
  if (!grant) throw new Error("Local workspace bootstrap returned no grant");
  workspaceId = grant.workspaceId;
  const token = randomBytes(32).toString("base64url");
  const key = await createOrganizationApiKey(client.db, {
    accountId: grant.accountId,
    name: "SEC-03 repro service key",
    prefix: "test",
    keyHash: createHash("sha256").update(token).digest("hex"),
    permissions: ["workspace:read"],
  });
  expect(key).toBeTruthy();
  serviceHeaders = { authorization: `Bearer ${token}` };
  const settings = testSettings({
    mcpServers: [
      { id: "protected-fixture", url: mcp.url, cacheToolsList: false, requireApproval: true },
    ],
  });
  const deps = {
    db: client.db,
    bus: new MemoryEventBus(),
    workflowClient: {} as never,
    managedAuth: null,
  };
  serviceApp = createApp({ ...deps, settings: { ...settings, productAccessMode: "managed" } });
  const serviceCatalog = await serviceApp.request(
    `/v1/workspaces/${workspaceId}/tools/catalog`,
    { headers: serviceHeaders },
  );
  expect(serviceCatalog.status).toBe(200);
  catalog = ToolGatewayCatalog.parse(await serviceCatalog.json());
  expect(catalog.entries).toEqual(
    expect.arrayContaining([
      expect.objectContaining({
        identity: { serverId: "protected-fixture", toolName: "search_documents" },
        approval: "human",
      }),
    ]),
  );
}, 180_000);

afterAll(async () => {
  mcp?.close();
  await client?.close();
  await shared?.release();
}, 60_000);

function callRequest() {
  return {
    operationId: randomUUID(),
    catalogDigest: catalog.digest,
    identity: { serverId: "protected-fixture", toolName: "search_documents" },
    arguments: { query: "SEC-03 repro" },
  };
}

describe("SEC-03 repro: service key vs human approval authority", () => {
  test("service key mints a human-approval token (VULNERABLE on base)", async () => {
    const response = await serviceApp.request(
      `/v1/workspaces/${workspaceId}/tools/approvals`,
      {
        method: "POST",
        headers: { ...serviceHeaders, "content-type": "application/json" },
        body: JSON.stringify(callRequest()),
      },
    );
    const body = await response.text();
    if (response.status === 201) {
      const parsed = ToolGatewayApprovalResponse.parse(JSON.parse(body));
      console.log(`SEC03_RESULT=VULNERABLE: service key minted approval token ${parsed.approvalToken.slice(0, 12)}…`);
    } else {
      console.log(`SEC03_RESULT=FIXED: approval denied status=${response.status} body=${body.slice(0, 160)}`);
    }
    // Record the outcome either way; the console line is the evidence.
    expect([201, 403]).toContain(response.status);
  });
});
