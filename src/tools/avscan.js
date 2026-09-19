// av_scan: scan files or directories for malware/adware using ClamAV or
// Windows Defender (MpCmdRun). Local scanning only; no cloud upload.
import { runShell, saveReport, finding, requireValue, readSetting } from "../lib/run.js";

const MAX_EVIDENCE = 20000;

function buildAvCommand(path, engine) {
  const p = requireValue(path, "path");
  const engineName = String(engine || "auto").toLowerCase();

  if (engineName === "clamav") {
    // --no-summary avoids the trailing summary line that confuses some parsers
    return `clamscan --no-summary --recursive ${p}`;
  }

  if (engineName === "defender" || engineName === "mpcmdrun") {
    // Windows Defender command-line scanner
    return `MpCmdRun.exe -Scan -ScanType 3 -File ${p}`;
  }

  // auto: prefer clamav, fall back to defender on Windows
  return `(clamscan --no-summary --recursive ${p}) || (MpCmdRun.exe -Scan -ScanType 3 -File ${p})`;
}

function parseClamav(text) {
  const findings = [];
  const lines = String(text || "").split(/\r?\n/);
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    // ClamAV prints "FOUND" for detections
    if (/FOUND/i.test(trimmed)) {
      const parts = trimmed.split(/:|\\s+/);
      const file = parts[0] || "unknown";
      const malware = trimmed.match(/([A-Za-z0-9_.-]+)\\s+FOUND/i);
      findings.push({
        severity: "high",
        file,
        malware: malware ? malware[1] : "unknown",
        engine: "clamav",
      });
    }
  }
  return findings;
}

function parseDefender(text) {
  const findings = [];
  // MpCmdRun output is verbose; look for threat names
  const lines = String(text || "").split(/\r?\n/);
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    if (/threat/i.test(trimmed) || /found/i.test(trimmed)) {
      findings.push({
        severity: "high",
        file: "scanned",
        malware: trimmed,
        engine: "defender",
      });
    }
  }
  return findings;
}

export function makeAvScanHandler(ctx) {
  return async function av_scan(args) {
    const path = requireValue(args.path, "path");
    const engine = args.engine || "auto";
    const command = buildAvCommand(path, engine);
    const output = await runShell(
      ctx,
      command,
      await toolOptions(ctx, { timeoutSecs: args.timeoutSecs ?? 300 }),
    );
    const text = [output?.stdout, output?.stderr].filter(Boolean).join("\n");
    const timedOut = !!(output && output.timed_out);
    const notFound = /(command not found|No such file|not installed)/i.test(text);

    if (notFound) {
      return {
        tool: "av_scan",
        target: path,
        command,
        status: "failed",
        error: `no AV engine found (install clamav or ensure Windows Defender is available)`,
        output: text.slice(0, MAX_EVIDENCE),
        findings: [
          {
            tool: "av_scan",
            target: path,
            severity: "error",
            summary: "av_scan: no supported AV engine installed on this host",
            evidence: text.slice(0, 4000),
          },
        ],
      };
    }

    let parsed = [];
    if (engine === "defender" || engine === "mpcmdrun") {
      parsed = parseDefender(text);
    } else {
      parsed = parseClamav(text);
      if (parsed.length === 0) parsed = parseDefender(text);
    }

    const severity = timedOut
      ? "warn"
      : parsed.length > 0
        ? "high"
        : "info";

    const summary = timedOut
      ? `AV scan of ${path} timed out`
      : parsed.length > 0
        ? `${parsed.length} malware/adware detection(s) in ${path}`
        : `no malware/adware detected in ${path}`;

    void saveReport(ctx, { tool: "av_scan", target: path, command, output, severity });

    return {
      tool: "av_scan",
      target: path,
      engine,
      command,
      status: timedOut ? "timed_out" : "completed",
      count: parsed.length,
      findings: parsed,
      output: text.slice(0, MAX_EVIDENCE),
      findings_report: [
        {
          tool: "av_scan",
          target: path,
          severity,
          summary,
          evidence: parsed.length
            ? parsed.map((f) => `[${f.engine}] ${f.malware} in ${f.file}`).join("\n")
            : "No malware/adware detected.",
        },
      ],
    };
  };
}
