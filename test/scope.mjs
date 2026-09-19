import { strict as assert } from "node:assert";

const SECURITY_TOOLS = new Set(["sast_scan", "dependency_audit", "av_scan"]);

assert(SECURITY_TOOLS.size === 3, "expect 3 security tools");
assert(SECURITY_TOOLS.has("sast_scan"), "missing sast_scan");
assert(SECURITY_TOOLS.has("dependency_audit"), "missing dependency_audit");
assert(SECURITY_TOOLS.has("av_scan"), "missing av_scan");

console.log("security kit scope: ok");
