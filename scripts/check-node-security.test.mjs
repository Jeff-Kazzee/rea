import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { nodeSecurityProblem } from "./check-node-security.mjs";

const disclosed = new Date("2026-10-21T00:00:00Z");
const rejected = [
  "22.19.0",
  "22.23.3",
  "24.15.0",
  "24.19.0",
  "24.21.0",
  "24.22.0",
  "26.12.0",
  "20.20.2",
  "25.1.0",
  "27.0.0",
  "28.0.0",
];

test("rejects affected releases, EOL lines and unreviewed new majors", () => {
  for (const version of rejected)
    assert.notEqual(nodeSecurityProblem(version, disclosed), null, version);
});

test("accepts the three fixed floors and later patches on supported lines", () => {
  for (const version of [
    "22.23.4",
    "24.22.1",
    "26.12.1",
    "22.24.0",
    "24.22.2",
    "26.13.0",
  ])
    assert.equal(nodeSecurityProblem(version, disclosed), null, version);
});

test("rejects malformed and prerelease versions", () => {
  for (const version of [
    "",
    "24",
    "24.22",
    "v24.22.1",
    "24.22.1-rc.1",
    "24.22.1\n",
    "24.22.1+build",
    null,
    24,
    "24.9007199254740992.1",
  ])
    assert.notEqual(
      nodeSecurityProblem(version, disclosed),
      null,
      String(version),
    );
});

test("expires each supported line at its declared UTC deadline", () => {
  for (const [version, deadline] of [
    ["22.23.4", "2027-04-30"],
    ["24.22.1", "2028-04-30"],
    ["26.12.1", "2029-04-30"],
  ]) {
    const end = new Date(`${deadline}T00:00:00Z`);
    assert.equal(nodeSecurityProblem(version, new Date(end.getTime() - 1)), null);
    assert.notEqual(nodeSecurityProblem(version, end), null);
  }
  assert.notEqual(nodeSecurityProblem("24.22.1", new Date("invalid")), null);
});

test("uses the actual executable despite spoofed environment and arguments", () => {
  const file = fileURLToPath(new URL("./check-node-security.mjs", import.meta.url));
  const result = spawnSync(process.execPath, [file, "20.20.2"], {
    encoding: "utf8",
    env: {
      ...process.env,
      NODE_VERSION: "20.20.2",
      NODE_OPTIONS: "",
      NODE_PATH: "",
    },
  });
  assert.equal(
    result.status,
    nodeSecurityProblem(process.versions.node) === null ? 0 : 1,
    result.stderr,
  );
});

test("the packaged launcher checks Node before loading application modules", () => {
  const launcher = readFileSync(new URL("./rea.mjs", import.meta.url), "utf8");
  assert.ok(
    launcher.includes(
      'import { assertNodeSecurity } from "./check-node-security.mjs"',
    ),
  );
  assert.ok(
    launcher.indexOf("assertNodeSecurity();") < launcher.indexOf("await import("),
  );
  const manifest = JSON.parse(
    readFileSync(new URL("../package.json", import.meta.url), "utf8"),
  );
  assert.ok(manifest.files.includes("scripts/check-node-security.mjs"));
});

test("build and publication commands check security before dependency commands", () => {
  const manifest = JSON.parse(
    readFileSync(new URL("../package.json", import.meta.url), "utf8"),
  );
  for (const command of [
    "build",
    "build:cached",
    "build:termux",
    "predocs:build",
    "docs:build",
    "prepublishOnly",
  ])
    assert.ok(
      manifest.scripts[command].startsWith("npm run security:check && "),
      command,
    );
  assert.ok(
    manifest.scripts["security:check"].startsWith(
      "node scripts/check-node-security.mjs && ",
    ),
  );
});
