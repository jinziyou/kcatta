#!/usr/bin/env node
/**
 * Generate TypeScript types from form/schemas-json/*.schema.json.
 *
 * Run from admin/:  pnpm generate:contracts
 * Output:           src/lib/schemas/*.ts (do not edit by hand)
 */

import { compile } from "json-schema-to-typescript";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const adminRoot = path.resolve(__dirname, "..");
const schemaDir = path.resolve(adminRoot, "../form/schemas-json");
const outDir = path.resolve(adminRoot, "src/lib/schemas");

const SCHEMAS = [
  "AgentIdentity",
  "AssetReport",
  "DetectionResult",
  "TraceBatch",
  "Alert",
  "AttackPath",
  "GuardEventBatch",
  "ScanTarget",
  "ScanTargetInput",
  "ScanJob",
  "TriggerScanRequest",
  "CredentialInfo",
  "CredentialActionRequest",
  "CredentialTestResult",
  "CredentialRevokeResult",
  "GuardLifecycleStatus",
];

const BANNER = `/**
 * AUTO-GENERATED — do not edit.
 *
 * Source: form/schemas-json/*.schema.json (the public control-plane contract).
 * Regenerate: \`pnpm generate:contracts\` from admin/
 */
`;

/** Compile each JSON schema in {@link SCHEMAS} into a TypeScript module under {@link outDir}. */
async function main() {
  await fs.mkdir(outDir, { recursive: true });

  for (const name of SCHEMAS) {
    const schemaPath = path.join(schemaDir, `${name}.schema.json`);
    const schema = JSON.parse(await fs.readFile(schemaPath, "utf8"));
    const ts = await compile(schema, name, {
      bannerComment: BANNER.trim(),
      unreachableDefinitions: true,
      enableConstEnums: false,
      additionalProperties: false,
    });
    await fs.writeFile(
      path.join(outDir, `${name}.ts`),
      `${ts.trimEnd()}\n`,
      "utf8",
    );
    console.log(`wrote src/lib/schemas/${name}.ts`);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
