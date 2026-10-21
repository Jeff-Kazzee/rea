import { createHash } from "node:crypto";
import { readFile, readdir } from "node:fs/promises";
import { join } from "node:path";

import { describe, expect, it } from "vitest";
import { parse } from "yaml";
import { z } from "zod";

const bootstrapId = "action-runtime-bootstrap";
const probeStart = "# Native hosted jobs only.";
const reviewedProbeSha256 =
  "1e078b8a740865abfea7c5d3310b5930a5c7e135f02f89e5f9d09dd0e37cf38d";
const clientId = "package-manager-client";
const gate = `steps.${bootstrapId}.outcome == 'success' && steps.${clientId}.outcome == 'success'`;
const clientHold =
  "throw 'CI_UNREVIEWED_PACKAGE_MANAGER_CLIENT: the npm/Yarn startup boundary has no approved advisory disposition. Review the actual clients and their bundled dependencies before removing this hold. A clean project lock audit does not clear the clients.'\n";
const stepSchema = z.object({
  id: z.string().optional(),
  if: z.string().optional(),
  uses: z.string().optional(),
  shell: z.string().optional(),
  run: z.string().optional(),
  "continue-on-error": z.boolean().optional(),
});
const workflowSchema = z.object({
  jobs: z.record(
    z.string(),
    z.object({
      steps: z.array(stepSchema).optional(),
      uses: z.string().optional(),
      if: z.union([z.string(), z.boolean()]).optional(),
      "continue-on-error": z.union([z.string(), z.boolean()]).optional(),
    }),
  ),
});
const manifestsSchema = z.array(
  z.object({
    use: z.string(),
    using: z.enum(["node20", "node24", "composite"]),
    pre: z.null(),
    nested: z.array(z.string()),
  }),
);
type Step = z.infer<typeof stepSchema>;

function assertStepGate(condition: string | undefined) {
  const value = z.string().parse(condition);
  const prefix = `\${{ ${gate}`;
  if (value === `${prefix} }}`) return;
  expect(value.startsWith(`${prefix} && (`)).toBe(true);
  expect(value.endsWith(") }}")).toBe(true);
  const wrapped = value.slice(prefix.length + 4, -3);
  let depth = 0;
  let quoted = false;
  for (let index = 0; index < wrapped.length; index++) {
    const character = wrapped[index];
    if (character === "'") {
      if (quoted && wrapped[index + 1] === "'") index++;
      else quoted = !quoted;
    } else if (!quoted) {
      if (character === "(") depth++;
      if (character === ")") depth--;
    }
    expect(depth).toBeGreaterThanOrEqual(index === wrapped.length - 1 ? 0 : 1);
  }
  expect(depth).toBe(0);
  expect(quoted).toBe(false);
}

function assertBootstrap(steps: Step[], runtimes: string[]) {
  const first = steps[0];
  expect(first?.id).toBe(bootstrapId);
  expect(first?.shell).toBe("pwsh");
  expect(first?.if).toBeUndefined();
  expect(first?.uses).toBeUndefined();
  expect(first?.["continue-on-error"]).not.toBe(true);
  const run = z.string().parse(first?.run);
  const marker = run.indexOf(probeStart);
  expect(marker).toBeGreaterThan(0);
  expect(
    createHash("sha256").update(run.slice(marker)).digest("hex"),
  ).toBe(reviewedProbeSha256);
  const list = runtimes.map((runtime) => `'${runtime}'`).join(", ");
  const expectedCaller =
    "# Caller contract from immutable action manifests. No pre hooks declared.\n" +
    `$requiredActionRuntimes = @(${list})\n` +
    "if (@($requiredActionRuntimes | Where-Object { $_ -cne 'node24' }).Count) {\n" +
    "  throw 'CI_UNSUPPORTED_ACTION_RUNTIME: this required job still declares Node 20 actions. Review compatible action replacements before execution. The node24 probe cannot clear Node 20.'\n}\n";
  expect(run.slice(0, marker)).toBe(expectedCaller);
  const client = steps[1];
  expect(client?.id).toBe(clientId);
  expect(client?.shell).toBe("pwsh");
  expect(client?.uses).toBeUndefined();
  expect(client?.["continue-on-error"]).not.toBe(true);
  expect(client?.if).toBe(`\${{ steps.${bootstrapId}.outcome == 'success' }}`);
  expect(client?.run).toBe(clientHold);
  for (const step of steps.slice(2)) assertStepGate(step.if);
}

describe("managed action interpreter policy", () => {
  it("binds every concrete job, nested action and diagnostic to the vetted bootstrap", async () => {
    const manifests = manifestsSchema.parse(
      JSON.parse(
        await readFile(".github/action-runtime-manifests.json", "utf8"),
      ),
    );
    const byUse = new Map(manifests.map((entry) => [entry.use, entry]));
    const runtimesFor = async (
      use: string,
      visited: string[] = [],
    ): Promise<string[]> => {
      expect(visited).not.toContain(use);
      const ancestry = [...visited, use];
      if (use.startsWith("./")) {
        const action = z
          .object({
            runs: z.object({
              using: z.literal("composite"),
              steps: z.array(stepSchema),
            }),
          })
          .parse(parse(await readFile(join(use, "action.yml"), "utf8")));
        return (
          await Promise.all(
            action.runs.steps
              .flatMap((step) => (step.uses ? [step.uses] : []))
              .map((child) => runtimesFor(child, ancestry)),
          )
        ).flat();
      }
      expect(use).toMatch(/^[^@]+@[0-9a-f]{40}$/u);
      const manifest = byUse.get(use);
      expect(manifest, `Unreviewed action: ${use}`).toBeDefined();
      if (!manifest) throw new Error(`Unreviewed action: ${use}`);
      if (manifest.using !== "composite") return [manifest.using];
      return (
        await Promise.all(
          manifest.nested.map((child) => runtimesFor(child, ancestry)),
        )
      ).flat();
    };
    let checked = 0;
    for (const file of await readdir(".github/workflows")) {
      if (!/\.ya?ml$/u.test(file)) continue;
      const workflow = workflowSchema.parse(
        parse(await readFile(join(".github/workflows", file), "utf8")),
      );
      for (const job of Object.values(workflow.jobs)) {
        if (file === "node-security.yml") {
          expect(job.if).toBeUndefined();
          expect(job["continue-on-error"]).toBeUndefined();
        }
        if (!job.steps) {
          expect(job.uses?.startsWith("./.github/workflows/")).toBe(true);
          continue;
        }
        const runtimes = (
          await Promise.all(
            job.steps
              .flatMap((step) => (step.uses ? [step.uses] : []))
              .map((use) => runtimesFor(use)),
          )
        ).flat();
        const required = [...new Set(runtimes)].sort();
        assertBootstrap(job.steps, required.length ? required : ["node24"]);
        checked++;
      }
      if (file === "ci.yml") {
        const securityJob = workflow.jobs["node-security"];
        expect(securityJob?.uses).toBe("./.github/workflows/node-security.yml");
        expect(securityJob?.if).toBeUndefined();
        expect(securityJob?.["continue-on-error"]).toBeUndefined();
      }
    }
    expect(checked).toBeGreaterThan(0);
  });

  it("rejects missing probes, omitted legacy runtimes and unguarded failure diagnostics", async () => {
    const workflow = workflowSchema.parse(
      parse(await readFile(".github/workflows/node-security.yml", "utf8")),
    );
    const steps = z.array(stepSchema).parse(workflow.jobs.policy?.steps);
    assertBootstrap(steps, ["node24"]);
    expect(() => assertBootstrap(steps.slice(1), ["node24"])).toThrow();
    expect(() => assertBootstrap(steps, ["node20", "node24"])).toThrow();
    const diagnostic = [
      ...steps,
      { uses: "unreviewed/action@main", if: "always()" },
    ];
    expect(() => assertBootstrap(diagnostic, ["node24"])).toThrow();
    expect(() => assertStepGate(`\${{ ${gate} || always() }}`)).toThrow();
    expect(() =>
      assertStepGate(`\${{ ${gate} && (false) || (always()) }}`),
    ).toThrow();
  });
});
