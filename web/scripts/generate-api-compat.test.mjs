import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { cp, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

test("unmapped model names require review", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "cheesetrap-api-contract-"));
  try {
    const web = path.join(root, "web");
    const scripts = path.join(web, "scripts");
    const generated = path.join(web, "src/api/generated");
    await Promise.all([mkdir(scripts, { recursive: true }), mkdir(generated, { recursive: true }), mkdir(path.join(root, "api"))]);
    await symlink(fileURLToPath(new URL("../node_modules", import.meta.url)), path.join(web, "node_modules"));
    const script = path.join(scripts, "generate-api-compat.mjs");
    const specPath = path.join(root, "api/openapi.json");
    await Promise.all([
      cp(new URL("./generate-api-compat.mjs", import.meta.url), script),
      cp(new URL("../src/api/generated/models.ts", import.meta.url), path.join(generated, "models.ts")),
      cp(new URL("../../api/openapi.json", import.meta.url), specPath),
    ]);
    execFileSync(process.execPath, [script]);
    const result = await readFile(path.join(web, "src/api/schema.d.ts"), "utf8");
    assert.doesNotMatch(result, /smtp|SMTP|Delivery|Approval/);
    const spec = JSON.parse(await readFile(specPath, "utf8"));
    spec.components.schemas["UnmappedModel"] = {type:"object", properties:{value:{type:"string"}}};
    await writeFile(specPath, JSON.stringify(spec));
    const changed = spawnSync(process.execPath, [script], { encoding: "utf8" });
    assert.notEqual(changed.status, 0);
    assert.match(changed.stderr, /Orval type mapping requires review: UnmappedModel/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
