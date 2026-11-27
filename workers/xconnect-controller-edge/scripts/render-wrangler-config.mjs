import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const PLACEHOLDER = "REPLACE_WITH_HYPERDRIVE_ID";

/**
 * Render wrangler configuration for deployment.
 * Injects a valid Hyperdrive ID if present; otherwise removes the placeholder
 * [[hyperdrive]] block so `wrangler deploy` can still deploy health/SSE-fallback routes.
 */
export function renderWranglerConfig(rawToml, hyperdriveId = "") {
  const trimmedId = (hyperdriveId ?? "").trim();
  if (trimmedId && trimmedId !== PLACEHOLDER) {
    if (trimmedId.includes('"') || trimmedId.includes("\n")) {
      throw new Error("invalid CLOUDFLARE_HYPERDRIVE_ID");
    }
    return {
      toml: rawToml.replace(`id = "${PLACEHOLDER}"`, `id = "${trimmedId}"`),
      hyperdriveConfigured: true,
    };
  }

  const stripped = rawToml.replace(
    /\[\[hyperdrive\]\][\s\S]*?(?=\n\[vars\]|\n\[|$)/,
    "",
  );
  return {
    toml: stripped.replace(/\n{3,}/g, "\n\n"),
    hyperdriveConfigured: false,
  };
}

function main() {
  const cwd = process.cwd();
  const inputPath = path.resolve(cwd, process.argv[2] || "wrangler.toml");
  const outputPath = path.resolve(cwd, process.argv[3] || "wrangler.deploy.toml");
  const rawToml = fs.readFileSync(inputPath, "utf8");
  const { toml, hyperdriveConfigured } = renderWranglerConfig(
    rawToml,
    process.env.CLOUDFLARE_HYPERDRIVE_ID || "",
  );
  fs.writeFileSync(outputPath, toml, "utf8");
  if (!hyperdriveConfigured) {
    console.log(
      "Notice: CLOUDFLARE_HYPERDRIVE_ID not set; deploying without [[hyperdrive]] binding (/healthz and SSE fallback active).",
    );
  } else {
    console.log("Rendered wrangler.deploy.toml with configured Hyperdrive binding.");
  }
}

const isEntrypoint =
  process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isEntrypoint) {
  main();
}
