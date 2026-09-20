// av_scan: scan files or directories for malware/adware using ClamAV,
// Windows Defender (MpCmdRun), or YARA rules. Local scanning only.
// Supports adware-only mode via YARA rules.
import { runShell, saveReport, finding, requireValue, readSetting } from "../lib/run.js";

const MAX_EVIDENCE = 20000;

// Minimal bundled adware YARA rules (fallback when no custom rules provided).
// These catch common adware families and PUP/adware indicators.
const BUNDLED_ADWARE_RULES = `
rule Adware_Generic_Bundle {
  strings:
    $adware1 = "adware" nocase
    $adware2 = "adware.dll" nocase
    $pup1 = "potentially unwanted" nocase
    $pup2 = "PUP" nocase
  condition:
    any of ($adware1, $adware2, $pup1, $pup2)
}

rule Adware_Browser_Hijacker {
  strings:
    $hijack1 = "browser hijack" nocase
    $hijack2 = "homepage" nocase
    $toolbar = "toolbar" nocase
  condition:
    2 of them
}

rule Adware_Tracker {
  strings:
    $track1 = "tracker" nocase
    $track2 = "analytics" nocase
    $adsdk = "adsdk" nocase
  condition:
    2 of them
}
`;

function buildYaraCommand(path, rulesPath, adwareOnly) {
  const p = requireValue(path, "path");
  // If adwareOnly is true and no custom rules provided, use bundled rules via stdin.
  if (adwareOnly && !rulesPath) {
    // Write bundled rules to a temp file, then scan.
    // Using a temp file because yara CLI prefers file paths over stdin for rules.
    return `printf '%s' '${BUNDLED_ADWARE_RULES.replace(/'/g, "'\\''")}' > /tmp/termigo-adware.yar && yara /tmp/termigo-adware.yar ${p}`;
  }
  const r = rulesPath ? ` ${rulesPath}` : "";
  return `yara ${r} ${p}`;
}

function buildAvCommand(path, engine) {
  const p = requireValue(path, "path");
  const engineName = String(engine || "auto").toLowerCase();

  if (engineName === "clamav") {
    return `clamscan --no-summary --recursive ${p}`;
  }

  if (engineName === "defender" || engineName === "mpcmdrun") {
    return `MpCmdRun.exe -Scan -ScanType 3 -File ${p}`;
  }

  // auto: prefer ClamAV across all platforms (Windows, macOS, Linux).
  // Defender is Windows-only and only used when explicitly selected.
  return `clamscan --no-summary --recursive ${p}`;
}

function parseClamav(text) {
  const findings = [];
  const lines = String(text || "").split(/\r?\n/);
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    if (/FOUND/i.test(trimmed)) {
      const file = trimmed.split(/:/)[0] || "unknown";
      const malware = trimmed.match(/([A-Za-z0-9_.-]+)\s+FOUND/i);
      findings.push({
        severity: "high",
        file,
        malware: malware ? malware[1] : "unknown",
        engine: "clamav",
        category: "malware",
      });
    }
  }
  return findings;
}

function parseDefender(text) {
  const findings = [];
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
        category: "malware",
      });
    }
  }
  return findings;
}

function parseYara(text) {
  const findings = [];
  const lines = String(text || "").split(/\r?\n/);
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    // YARA output: <rule_name> <file_path>
    const m = trimmed.match(/^([A-Za-z0-9_]+)\s+(.+)$/);
    if (m) {
      const ruleName = m[1];
      const file = m[2];
      const isAdwareRule = /adware|pup|tracker|browser|toolbar|hijack/i.test(ruleName);
      findings.push({
        severity: isAdwareRule ? "medium" : "high",
        file,
        malware: ruleName,
        engine: "yara",
        category: isAdwareRule ? "adware" : "malware",
      });
    }
  }
  return findings;
}

export function makeAvScanHandler(ctx) {
  return async function av_scan(args) {
    const path = requireValue(args.path, "path");
    const engine = args.engine || "auto";
    const adwareOnly = !!args.adwareOnly;
    const yaraRules = args.yaraRules || "";
    const command = adwareOnly
      ? buildYaraCommand(path, yaraRules, adwareOnly)
      : buildAvCommand(path, engine);
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
        error: `no AV engine found (install clamav for cross-platform support, yara for adware rules, or Windows Defender on Windows)`,
        output: text.slice(0, MAX_EVIDENCE),
        findings: [
          {
            tool: "av_scan",
            target: path,
            severity: "error",
            summary: "av_scan: no supported AV engine installed. Install clamav (brew/apt) or yara (brew/apt/go install).",
            evidence: text.slice(0, 4000),
          },
        ],
      };
    }

    let parsed = [];
    if (adwareOnly) {
      parsed = parseYara(text);
    } else if (engine === "defender" || engine === "mpcmdrun") {
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
        ? `${parsed.length} detection(s) in ${path}${adwareOnly ? " (adware-only)" : ""}`
        : `no malware/adware detected in ${path}${adwareOnly ? " (adware-only)" : ""}`;

    void saveReport(ctx, { tool: "av_scan", target: path, command, output, severity });

    return {
      tool: "av_scan",
      target: path,
      engine: adwareOnly ? "yara" : engine,
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
            ? parsed.map((f) => `[${f.engine}/${f.category}] ${f.malware} in ${f.file}`).join("\n")
            : "No malware/adware detected.",
        },
      ],
    };
  };
}
