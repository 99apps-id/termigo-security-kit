// dependency_audit: scan project dependencies for known vulnerabilities
// using osv-scanner, npm audit, pip audit, cargo audit, or govulncheck.
// Local filesystem only; does not exfiltrate manifests.
import { runShell, saveReport, finding, requireValue, readSetting } from "../lib/run.js";

const MAX_EVIDENCE = 20000;

function buildDepCommand(path, ecosystem) {
  const p = requireValue(path, "path");
  const eco = String(ecosystem || "auto").toLowerCase();

  if (eco === "npm" || eco === "auto") {
    return `cd ${p} && npm audit --json || true`;
  }
  if (eco === "pip" || eco === "python") {
    return `cd ${p} && pip audit --json || true`;
  }
  if (eco === "cargo" || eco === "rust") {
    return `cd ${p} && cargo audit --json || true`;
  }
  if (eco === "go") {
    return `cd ${p} && govulncheck ./... || true`;
  }
  if (eco === "osv") {
    return `osv-scanner --json ${p} || true`;
  }

  // auto: try osv-scanner first (multi-ecosystem), fall back to npm audit
  return `osv-scanner --json ${p} || (cd ${p} && npm audit --json || true)`;
}

function parseNpmAudit(text) {
  const findings = [];
  try {
    const json = JSON.parse(text);
    if (json.vulnerabilities && typeof json.vulnerabilities === "object") {
      for (const [name, vuln] of Object.entries(json.vulnerabilities)) {
        const severity = (vuln.severity || "medium").toLowerCase();
        findings.push({
          severity,
          package: name,
          rule: vuln.via?.[0]?.url || "N/A",
          message: vuln.via?.[0]?.title || `Vulnerability in ${name}`,
          line: undefined,
        });
      }
    }
  } catch {
    // not JSON
  }
  return findings;
}

function parsePipAudit(text) {
  const findings = [];
  try {
    const json = JSON.parse(text);
    if (Array.isArray(json.dependencies)) {
      for (const dep of json.dependencies) {
        if (Array.isArray(dep.vulns)) {
          for (const v of dep.vulns) {
            findings.push({
              severity: (v.advisory?.severity || "medium").toLowerCase(),
              package: dep.name,
              rule: v.advisory?.id || "N/A",
              message: v.advisory?.summary || "",
              line: undefined,
            });
          }
        }
      }
    }
  } catch {
    // not JSON
  }
  return findings;
}

function parseOsvScanner(text) {
  const findings = [];
  try {
    const json = JSON.parse(text);
    if (Array.isArray(json.results)) {
      for (const result of json.results) {
        if (Array.isArray(result.packages)) {
          for (const pkg of result.packages) {
            for (const vuln of pkg.vulnerabilities || []) {
              findings.push({
                severity: (vuln.severity?.[0] || "medium").toLowerCase(),
                package: pkg.name,
                rule: vuln.id || "N/A",
                message: vuln.summary || "",
                line: undefined,
              });
            }
          }
        }
      }
    }
  } catch {
    // not JSON
  }
  return findings;
}

export function makeDependencyAuditHandler(ctx) {
  return async function dependency_audit(args) {
    const path = requireValue(args.path, "path");
    const ecosystem = args.ecosystem || "auto";
    const command = buildDepCommand(path, ecosystem);
    const output = await runShell(
      ctx,
      command,
      await toolOptions(ctx, { timeoutSecs: args.timeoutSecs ?? 180 }),
    );
    const text = [output?.stdout, output?.stderr].filter(Boolean).join("\n");
    const timedOut = !!(output && output.timed_out);
    const notFound = /(command not found|No such file|not installed)/i.test(text);

    if (notFound) {
      return {
        tool: "dependency_audit",
        target: path,
        command,
        status: "failed",
        error: `no dependency audit tool found (install osv-scanner, npm audit, pip audit, cargo audit, or govulncheck)`,
        output: text.slice(0, MAX_EVIDENCE),
        findings: [
          {
            tool: "dependency_audit",
            target: path,
            severity: "error",
            summary: "dependency_audit: no supported audit tool installed on this host",
            evidence: text.slice(0, 4000),
          },
        ],
      };
    }

    let parsed = [];
    if (ecosystem === "pip" || ecosystem === "python") {
      parsed = parsePipAudit(text);
    } else if (ecosystem === "osv" || ecosystem === "auto") {
      parsed = parseOsvScanner(text);
    } else {
      parsed = parseNpmAudit(text);
      if (parsed.length === 0) parsed = parseOsvScanner(text);
    }

    const severity = timedOut
      ? "warn"
      : parsed.length > 10
        ? "high"
        : parsed.length > 0
          ? "medium"
          : "info";

    const summary = timedOut
      ? `dependency audit of ${path} timed out`
      : `${parsed.length} vulnerable dependency/ies found in ${path} (${ecosystem})`;

    void saveReport(ctx, { tool: "dependency_audit", target: path, command, output, severity });

    return {
      tool: "dependency_audit",
      target: path,
      ecosystem,
      command,
      status: timedOut ? "timed_out" : "completed",
      count: parsed.length,
      findings: parsed,
      output: text.slice(0, MAX_EVIDENCE),
      findings_report: [
        {
          tool: "dependency_audit",
          target: path,
          severity,
          summary,
          evidence: parsed.length
            ? parsed.map((f) => `[${f.severity}] ${f.package}: ${f.message} (${f.rule})`).join("\n")
            : "No vulnerable dependencies detected.",
        },
      ],
    };
  };
}
