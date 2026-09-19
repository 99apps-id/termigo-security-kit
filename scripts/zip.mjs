// Package the extension into an installable .zip for Termigo.
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { createHash } from "node:crypto";

const OUT = "termigo-security-kit.zip";
const MANIFEST = "manifest.json";
const isWindows = process.platform === "win32";

if (!existsSync(MANIFEST)) {
  console.error(`missing: ${MANIFEST}`);
  process.exit(1);
}

const manifest = JSON.parse(readFileSync(MANIFEST, "utf8"));
const main = manifest.main;
if (!main) {
  console.error("manifest.json has no `main`; Termigo would refuse the install");
  process.exit(1);
}

const targets = [MANIFEST, dirname(main)];
for (const target of targets) {
  if (!existsSync(target)) {
    console.error(`missing: ${target}`);
    process.exit(1);
  }
}

const packed = isWindows
  ? spawnSync("tar", ["-a", "-c", "-f", OUT, ...targets], { stdio: "inherit" })
  : spawnSync("zip", ["-r", OUT, ...targets], { stdio: "inherit" });

if (packed.status !== 0) process.exit(packed.status ?? 1);

const listing = spawnSync(
  isWindows ? "tar" : "unzip",
  isWindows ? ["-t", "-f", OUT] : ["-l", OUT],
  { encoding: "utf8" },
);
if (listing.status !== 0) {
  console.error(`could not read back ${OUT}`);
  process.exit(1);
}

const names = (listing.stdout ?? "")
  .split(/\r?\n/)
  .map((line) => line.trim().split(/\s+/).pop())
  .filter(Boolean);

const missing = [MANIFEST, main].filter((name) => !names.includes(name));
if (missing.length > 0) {
  console.error(
    `${OUT} is not installable: ${missing.join(", ")} missing from the archive.\n` +
      "Entry names must use forward slashes and sit at the archive root.",
  );
  process.exit(1);
}

const zipBytes = readFileSync(OUT);
const sha256 = createHash("sha256").update(zipBytes).digest("hex");
const shaFile = `${OUT}.sha256`;
writeFileSync(shaFile, `${sha256}  ${OUT}\n`);
console.log(`wrote ${OUT} and ${shaFile}`);
