import { fileURLToPath } from "node:url";

// October 21, 2026 fixes include Brotli RCE CVE-2026-111497 and eMudhra.
// https://nodejs.org/en/blog/vulnerability/october-2026-security-releases
const RELEASES = new Map([
  [22, { minimum: [22, 23, 4], until: "2027-04-30" }],
  [24, { minimum: [24, 22, 1], until: "2028-04-30" }],
  [26, { minimum: [26, 12, 1], until: "2029-04-30" }],
]);

export function nodeSecurityProblem(version, now = new Date()) {
  const match =
    typeof version === "string"
      ? /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.exec(version)
      : null;
  if (match === null || match[0] !== version)
    return "Node.js must report a complete stable version";
  const parts = version.split(".").map(Number);
  if (!parts.every(Number.isSafeInteger)) return "Node.js version is invalid";
  const release = RELEASES.get(parts[0]);
  if (release === undefined)
    return `Node.js ${version} has no supported, reviewed release line`;
  if (!(now instanceof Date) || !Number.isFinite(now.getTime()))
    return "Node.js support could not be checked against the current date";
  if (now >= new Date(`${release.until}T00:00:00Z`))
    return `Node.js ${parts[0]} is past this policy's support deadline`;
  for (let index = 0; index < parts.length; index++) {
    if (parts[index] > release.minimum[index]) return null;
    if (parts[index] < release.minimum[index])
      return `Node.js ${version} is below the security minimum ${release.minimum.join(".")}`;
  }
  return null;
}

export function assertNodeSecurity() {
  const problem = nodeSecurityProblem(process.versions.node);
  if (problem !== null) {
    process.stderr.write(
      `${problem}. Use Node.js 22.23.4, 24.22.1 or 26.12.1, or a reviewed later patch in those supported lines.\n`,
    );
    process.exit(1);
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) assertNodeSecurity();
