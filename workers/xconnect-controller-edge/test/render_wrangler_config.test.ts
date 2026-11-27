import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { renderWranglerConfig } from "../scripts/render-wrangler-config.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const baseToml = fs.readFileSync(path.resolve(__dirname, "../wrangler.toml"), "utf8");

test("renderWranglerConfig injects non-placeholder Hyperdrive ID", () => {
  const res = renderWranglerConfig(baseToml, "hd-1234567890abcdef");
  assert.equal(res.hyperdriveConfigured, true);
  assert.match(res.toml, /\[\[hyperdrive\]\]/);
  assert.match(res.toml, /id = "hd-1234567890abcdef"/);
  assert.match(res.toml, /\[vars\]/);
  assert.doesNotMatch(res.toml, /REPLACE_WITH_HYPERDRIVE_ID/);
});

test("renderWranglerConfig strips placeholder Hyperdrive block when missing", () => {
  const res = renderWranglerConfig(baseToml, "");
  assert.equal(res.hyperdriveConfigured, false);
  assert.doesNotMatch(res.toml, /\[\[hyperdrive\]\]/);
  assert.doesNotMatch(res.toml, /REPLACE_WITH_HYPERDRIVE_ID/);
  assert.match(res.toml, /name = "xconnect-controller-edge"/);
  assert.match(res.toml, /\[vars\]/);
  assert.match(res.toml, /ACCOUNTS_JWKS_URL/);
});

test("renderWranglerConfig strips placeholder Hyperdrive block when placeholder value passed", () => {
  const res = renderWranglerConfig(baseToml, "REPLACE_WITH_HYPERDRIVE_ID");
  assert.equal(res.hyperdriveConfigured, false);
  assert.doesNotMatch(res.toml, /\[\[hyperdrive\]\]/);
});
