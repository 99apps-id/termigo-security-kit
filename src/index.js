// Termigo Security Kit entry point.
// Registers non-pentest security tools: SAST, Dependency Audit, AV/Malware Scanner.
import { makeSastScanHandler } from "./tools/sast.js";
import { makeDependencyAuditHandler } from "./tools/depaudit.js";
import { makeAvScanHandler } from "./tools/avscan.js";

export function registerSecurityTools(ctx) {
  return {
    sast_scan: makeSastScanHandler(ctx),
    dependency_audit: makeDependencyAuditHandler(ctx),
    av_scan: makeAvScanHandler(ctx),
  };
}
