import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";

import { MacOSKeychainStorageManager } from "../src/storage/keychain-storage";

const serviceName = "oms-client-agent-mcp:keychain-smoke-test";
const key = `smoke-${randomUUID()}`;
const value = `value-${randomUUID()}`;
const storage = new MacOSKeychainStorageManager(serviceName);

try {
  assert.equal(storage.get(key), null, "new test key should not exist");

  storage.set(key, value);
  assert.equal(storage.get(key), value, "stored value should round-trip");

  storage.delete(key);
  assert.equal(storage.get(key), null, "deleted test key should not exist");

  console.log(
    JSON.stringify(
      {
        ok: true,
        serviceName,
        key,
        checks: ["missing-before-set", "set-get-roundtrip", "delete-removes-key"],
      },
      null,
      2,
    ),
  );
} catch (error) {
  try {
    storage.delete(key);
  } catch {
    // Best-effort cleanup; preserve the original failure below.
  }

  throw error;
}
