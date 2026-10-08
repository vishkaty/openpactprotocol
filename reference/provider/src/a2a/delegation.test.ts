import { randomUUID } from "node:crypto";
import { PGlite } from "@electric-sql/pglite";
import {
  createLocalJWKSet,
  exportJWK,
  generateKeyPair,
  SignJWT,
  type CryptoKey,
  type JWK,
} from "jose";
import { eq } from "drizzle-orm";
import { drizzle } from "drizzle-orm/pglite";
import { migrate } from "drizzle-orm/pglite/migrator";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { DELEGATION_HEADER, PACT_METADATA } from "@openpactprotocol/protocol/delegation";
import { createA2AHandler, type A2AHandler } from "./handler.js";
import type { Db } from "../db/client.js";
import { agentPlatforms, delegationGrants, schema } from "../db/schema.js";
import { seedDatabase } from "../db/seed.js";
import { delegationUrls } from "../delegation/config.js";
import { signDelegationToken } from "../delegation/tokens.js";

// Spec §5.5 (2): the Provider MUST verify that the delegation token's `client_id`
// equals the calling personal agent's `iss`.

const origin = "http://provider.test";
const issuer = "http://localhost:3002";
const defaultAudience = `${origin}/a2a`;
const scope = "flights:upcoming:read";
const brandUserId = "alex.rivera@example.com";

let pglite: PGlite;
let testDb: Db;
let handler: A2AHandler;
let skylineId = "";
let signingKey: CryptoKey;
let publicJwk: JWK & { kid: string };
let otherIssuer = "";
let grantId = "";

const savedEnv: Record<string, string | undefined> = {};
function setEnv(name: string, value: string): void {
  savedEnv[name] = process.env[name];
  process.env[name] = value;
}

async function signPlatformJwt(options: { issuer?: string } = {}): Promise<string> {
  const iat = Math.floor(Date.now() / 1000);
  return new SignJWT({ sub: "user-1" })
    .setProtectedHeader({ alg: "ES256", kid: publicJwk.kid, typ: "JWT" })
    .setIssuer(options.issuer ?? issuer)
    .setAudience(defaultAudience)
    .setIssuedAt(iat)
    .setExpirationTime(iat + 120)
    .sign(signingKey);
}

// A token the Provider itself would have issued for the grant below, which belongs to
// the personal agent at `issuer`.
function delegationToken(clientId: string): Promise<string> {
  const urls = delegationUrls(origin, skylineId);
  return signDelegationToken(
    {
      iss: urls.issuer,
      aud: urls.interfaceUrl,
      sub: brandUserId,
      client_id: clientId,
      scope,
      grant_id: grantId,
    },
    { now: new Date(), ttlSeconds: 3600 },
  );
}

// The text classifies to no delegated intent, so the turn is served without calling the
// Brand API. The reply still carries a receipt (§5.6) because a delegation token was
// accepted, and the receipt claims are what identify the grant it was accepted for.
async function sendWithDelegation(platformJwt: string, token: string): Promise<Response> {
  const request = new Request(`${origin}/a2a/${skylineId}/message:send`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${platformJwt}`,
      [DELEGATION_HEADER]: `Bearer ${token}`,
      "A2A-Version": "1.0",
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      message: {
        messageId: randomUUID(),
        role: "ROLE_USER",
        parts: [{ text: "Hello, I have a general question." }],
      },
    }),
  });
  return handler(request, skylineId, ["message:send"]);
}

describe("A2A delegated authority (spec §5.5)", () => {
  beforeAll(async () => {
    setEnv("A2A_AUDIENCE", defaultAudience);
    setEnv("PROVIDER_URL", origin);
    setEnv("DELEGATION_ENABLED", "1");
    const provider = await generateKeyPair("ES256", { extractable: true });
    setEnv("PROVIDER_PRIVATE_JWK", JSON.stringify(await exportJWK(provider.privateKey)));

    const platformKeys = await generateKeyPair("ES256", { extractable: true });
    signingKey = platformKeys.privateKey;
    publicJwk = {
      ...(await exportJWK(platformKeys.publicKey)),
      kid: `pa-${randomUUID()}`,
      alg: "ES256",
    } as JWK & { kid: string };

    pglite = new PGlite();
    const database = drizzle(pglite, { schema });
    await migrate(database, {
      migrationsFolder: new URL("../../drizzle", import.meta.url).pathname,
    });
    testDb = database as unknown as Db;
    const seeded = await seedDatabase(testDb, issuer, { seedDemoPlatform: true });
    skylineId = seeded.skylineId;

    // A second personal agent: its own issuer, the same JWKS, enabled. Same shape as
    // the `rsa-platform` row in handler.test.ts.
    otherIssuer = `${issuer}/other-pa`;
    await testDb.insert(agentPlatforms).values({
      name: "other-pa",
      issuer: otherIssuer,
      jwksUri: `${issuer}/.well-known/jwks.json`,
      enabled: true,
      audience: null,
    });

    // The grant belongs to the first personal agent.
    const platform = await testDb.query.agentPlatforms.findFirst({
      where: eq(agentPlatforms.issuer, issuer),
    });
    if (!platform) throw new Error("demo platform was not seeded");
    grantId = `a2agrant_${randomUUID()}`;
    await testDb.insert(delegationGrants).values({
      id: grantId,
      customerId: skylineId,
      platformId: platform.id,
      clientId: issuer,
      brandUserId,
      scope,
      expiresAt: new Date(Date.now() + 3_600_000),
    });

    const localJwks = createLocalJWKSet({ keys: [publicJwk] });
    handler = createA2AHandler({ db: testDb, getJwks: () => localJwks });
  });

  afterAll(async () => {
    await pglite?.close();
    for (const [name, value] of Object.entries(savedEnv)) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  });

  it("accepts a delegation token from the personal agent it was issued to", async () => {
    const response = await sendWithDelegation(
      await signPlatformJwt(),
      await delegationToken(issuer),
    );
    expect(response.status).toBe(200);
    const body = (await response.json()) as { message: { metadata?: Record<string, unknown> } };
    const receipt = body.message.metadata?.[PACT_METADATA.receipt] as
      | { claims: Record<string, unknown> }
      | undefined;
    expect(receipt?.claims).toMatchObject({ grantId, pa: issuer, user: brandUserId });
  });

  it("rejects a delegation token issued to a different personal agent", async () => {
    const response = await sendWithDelegation(
      await signPlatformJwt({ issuer: otherIssuer }),
      await delegationToken(issuer),
    );
    expect(response.status).toBe(401);
    // Distinguishes a rejected delegation token from a rejected personal-agent JWT,
    // which answers with `Bearer realm="a2a"` and no error.
    expect(response.headers.get("www-authenticate")).toBe(
      'Bearer realm="a2a", error="invalid_token"',
    );
    expect(await response.text()).toBe("");
  });
});
