// sast_scan: run static application security testing (SAST) on a local
// codebase using available engines (semgrep, bandit, gosec, eslint-plugin-security).
// Local-path scanning; never sends data off-box.
import { runShell, saveReport, finding, requireValue, readSetting } from "../lib/run.js";

const MAX_EVIDENCE = 20000;

function buildSastCommand(path, engines) {
  const p = requireValue(path, "path");
  const engineList = Array.isArray(engines) ? engines : ["semgrep"];
  const cmds = [];

  for (const engine of engineList) {
    switch (engine.toLowerCase()) {
      case "semgrep":
        cmds.push(`semgrep scan --config=auto ${p} --json --quiet`);
        break;
      case "bandit":
        cmds.push(`bandit -r ${p} -f json`);
        break;
      case "gosec":
        cmds.push(`gosec ${p}`);
        break;
      case "eslint":
        cmds.push(`eslint ${p} --plugin security --format json`);
        break;
      default:
        continue;
    }
  }

  return cmds.join(" && ");
}

function parseSemgrep(text) {
  const findings = [];
  try {
    const json = JSON.parse(text);
    if (Array.isArray(json.results)) {
      for (const r of json.results.slice(0, 100)) {
        findings.push({
          severity: r.extra?.severity || "medium",
          rule: r.check_id,
          message: r.extra?.message || "",
          file: r.path,
          line: r.start?.line,
        });
      }
    }
  } catch {
    // not JSON, treat as text
  }
  return findings;
}

function parseBandit(text) {
  const findings = [];
  try {
    const json = JSON.parse(text);
    if (Array.isArray(json.results)) {
      for (const r of json.results.slice(0, 100)) {
        findings.push({
          severity: (r.issue_severity || "").toLowerCase() || "medium",
          rule: r.test_id,
          message: r.issue_text || "",
          file: r.filename,
          line: r.line_number,
        });
      }
    }
  } catch {
    // not JSON
  }
  return findings;
}

export function makeSastScanHandler(ctx) {
  return async function sast_scan(args) {
    const path = requireValue(args.path, "path");
    const engines = Array.isArray(args.engines) ? args.engines : ["semgrep"];
    const command = buildSastCommand(path, engines);
    const output = await runShell(
      ctx,
      command,
      await toolOptions(ctx, { timeoutSecs: args.timeoutSecs ?? 300 }),
    );
    const text = [output?.stdout, output?.stderr].filter(Boolean).join("\n");
    const timedOut = !!(output && output.timed_out);
    const notFound = /(command not found|No such file|not installed)/i.test(text);
    const exitCode = output && typeof output === "object" ? output.exit_code : 0;

    if (notFound) {
      return {
        tool: "sast_scan",
        target: path,
        command,
        status: "failed",
        error: `one or more SAST engines (${engines.join(", ")}) are not installed`,
        output: text.slice(0, MAX_EVIDENCE),
        findings: [
          {
            tool: "sast_scan",
            target: path,
            severity: "error",
            summary: `sast_scan: engine not installed; install semgrep, bandit, gosec, or eslint-plugin-security`,
            evidence: text.slice(0, 4000),
          },
        ],
      };
    }

    let parsed = [];
    for (const engine of engines) {
      const engineText = text; // combined output; parse what we can
      if (engine.toLowerCase() === "semgrep") parsed.push(...parseSemgrep(engineText));
      if (engine.toLowerCase() === "bandit") parsed.push(...parseBandit(engineText));
    }

    const severity = timedOut
      ? "warn"
      : parsed.length > 10
        ? "high"
        : parsed.length > 0
          ? "medium"
          : "info";

    const summary = timedOut
      ? `SAST scan of ${path} timed out`
      : `${parsed.length} finding(s) found in ${path} (${engines.join(", ")})`;

    void saveReport(ctx, { tool: "sast_scan", target: path, command, output, severity });

    return {
      tool: "sast_scan",
      target: path,
      engines,
      command,
      status: timedOut ? "timed_out" : "completed",
      count: parsed.length,
      findings: parsed,
      output: text.slice(0, MAX_EVIDENCE),
      findings_report: [
        {
          tool: "sast_scan",
          target: path,
          severity,
          summary,
          evidence: parsed.length
            ? parsed.map((f) => `[${f.severity}] ${f.rule}: ${f.message} (${f.file}:${f.line || "?"})`).join("\n")
            : "No SAST findings detected.",
        },
      ],
    };
  };
}
