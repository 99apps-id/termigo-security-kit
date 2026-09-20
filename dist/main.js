// src/lib/run.js
async function runShell(ctx, command, { cwd, timeoutSecs } = {}) {
  return ctx.invoke("shell_run_command", {
    command,
    cwd: cwd || void 0,
    timeout_secs: timeoutSecs || void 0
  });
}
function requireValue(value, label) {
  const trimmed = value == null ? "" : String(value).trim();
  if (!trimmed) {
    throw new Error(`${label} cannot be empty`);
  }
  return trimmed;
}
async function readSetting(ctx, key, fallback = "") {
  try {
    const v = await ctx.settings.get(key);
    return v == null ? fallback : String(v);
  } catch {
    return fallback;
  }
}
async function saveReport(ctx, { tool, target, command, output, severity = "info" }) {
  try {
    const workingDir = (await readSetting(ctx, "security.workingDir")).trim().replace(/[\\/]+$/, "");
    const rel = `${(workingDir || "security-reports").replace(/[\\/]+$/, "")}/${tool}-${(target || "unknown").replace(/[^\w.-]+/g, "_")}-${(/* @__PURE__ */ new Date()).toISOString().replace(/[:.]/g, "-")}.md`;
    const text = output && output.stdout ? output.stdout : String(output || "");
    const content = [
      `# ${tool} report`,
      "",
      `- **Tool:** ${tool}`,
      `- **Target:** ${target || "n/a"}`,
      `- **Command:** \`${command || ""}\``,
      `- **Severity:** ${severity}`,
      `- **Time:** ${(/* @__PURE__ */ new Date()).toISOString()}`,
      "",
      "## Output",
      "",
      "```",
      String(text).slice(0, 2e4),
      "```",
      ""
    ].join("\n");
    await ctx.invoke("fs_write_file", { path: rel, content });
    return rel;
  } catch (e) {
    try {
      ctx.logger.warn(`report save failed: ${String(e)}`);
    } catch {
    }
    return null;
  }
}

// src/tools/sast.js
var MAX_EVIDENCE = 2e4;
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
          line: r.start?.line
        });
      }
    }
  } catch {
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
          line: r.line_number
        });
      }
    }
  } catch {
  }
  return findings;
}
function makeSastScanHandler(ctx) {
  return async function sast_scan(args) {
    const path = requireValue(args.path, "path");
    const engines = Array.isArray(args.engines) ? args.engines : ["semgrep"];
    const command = buildSastCommand(path, engines);
    const output = await runShell(
      ctx,
      command,
      await toolOptions(ctx, { timeoutSecs: args.timeoutSecs ?? 300 })
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
            evidence: text.slice(0, 4e3)
          }
        ]
      };
    }
    let parsed = [];
    for (const engine of engines) {
      const engineText = text;
      if (engine.toLowerCase() === "semgrep") parsed.push(...parseSemgrep(engineText));
      if (engine.toLowerCase() === "bandit") parsed.push(...parseBandit(engineText));
    }
    const severity = timedOut ? "warn" : parsed.length > 10 ? "high" : parsed.length > 0 ? "medium" : "info";
    const summary = timedOut ? `SAST scan of ${path} timed out` : `${parsed.length} finding(s) found in ${path} (${engines.join(", ")})`;
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
          evidence: parsed.length ? parsed.map((f) => `[${f.severity}] ${f.rule}: ${f.message} (${f.file}:${f.line || "?"})`).join("\n") : "No SAST findings detected."
        }
      ]
    };
  };
}

// src/tools/depaudit.js
var MAX_EVIDENCE2 = 2e4;
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
          line: void 0
        });
      }
    }
  } catch {
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
              line: void 0
            });
          }
        }
      }
    }
  } catch {
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
                line: void 0
              });
            }
          }
        }
      }
    }
  } catch {
  }
  return findings;
}
function makeDependencyAuditHandler(ctx) {
  return async function dependency_audit(args) {
    const path = requireValue(args.path, "path");
    const ecosystem = args.ecosystem || "auto";
    const command = buildDepCommand(path, ecosystem);
    const output = await runShell(
      ctx,
      command,
      await toolOptions(ctx, { timeoutSecs: args.timeoutSecs ?? 180 })
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
        output: text.slice(0, MAX_EVIDENCE2),
        findings: [
          {
            tool: "dependency_audit",
            target: path,
            severity: "error",
            summary: "dependency_audit: no supported audit tool installed on this host",
            evidence: text.slice(0, 4e3)
          }
        ]
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
    const severity = timedOut ? "warn" : parsed.length > 10 ? "high" : parsed.length > 0 ? "medium" : "info";
    const summary = timedOut ? `dependency audit of ${path} timed out` : `${parsed.length} vulnerable dependency/ies found in ${path} (${ecosystem})`;
    void saveReport(ctx, { tool: "dependency_audit", target: path, command, output, severity });
    return {
      tool: "dependency_audit",
      target: path,
      ecosystem,
      command,
      status: timedOut ? "timed_out" : "completed",
      count: parsed.length,
      findings: parsed,
      output: text.slice(0, MAX_EVIDENCE2),
      findings_report: [
        {
          tool: "dependency_audit",
          target: path,
          severity,
          summary,
          evidence: parsed.length ? parsed.map((f) => `[${f.severity}] ${f.package}: ${f.message} (${f.rule})`).join("\n") : "No vulnerable dependencies detected."
        }
      ]
    };
  };
}

// src/tools/avscan.js
var MAX_EVIDENCE3 = 2e4;
var BUNDLED_ADWARE_RULES = `
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
  if (adwareOnly && !rulesPath) {
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
        category: "malware"
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
        category: "malware"
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
        category: isAdwareRule ? "adware" : "malware"
      });
    }
  }
  return findings;
}
function makeAvScanHandler(ctx) {
  return async function av_scan(args) {
    const path = requireValue(args.path, "path");
    const engine = args.engine || "auto";
    const adwareOnly = !!args.adwareOnly;
    const yaraRules = args.yaraRules || "";
    const command = adwareOnly ? buildYaraCommand(path, yaraRules, adwareOnly) : buildAvCommand(path, engine);
    const output = await runShell(
      ctx,
      command,
      await toolOptions(ctx, { timeoutSecs: args.timeoutSecs ?? 300 })
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
        output: text.slice(0, MAX_EVIDENCE3),
        findings: [
          {
            tool: "av_scan",
            target: path,
            severity: "error",
            summary: "av_scan: no supported AV engine installed. Install clamav (brew/apt) or yara (brew/apt/go install).",
            evidence: text.slice(0, 4e3)
          }
        ]
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
    const severity = timedOut ? "warn" : parsed.length > 0 ? "high" : "info";
    const summary = timedOut ? `AV scan of ${path} timed out` : parsed.length > 0 ? `${parsed.length} detection(s) in ${path}${adwareOnly ? " (adware-only)" : ""}` : `no malware/adware detected in ${path}${adwareOnly ? " (adware-only)" : ""}`;
    void saveReport(ctx, { tool: "av_scan", target: path, command, output, severity });
    return {
      tool: "av_scan",
      target: path,
      engine: adwareOnly ? "yara" : engine,
      command,
      status: timedOut ? "timed_out" : "completed",
      count: parsed.length,
      findings: parsed,
      output: text.slice(0, MAX_EVIDENCE3),
      findings_report: [
        {
          tool: "av_scan",
          target: path,
          severity,
          summary,
          evidence: parsed.length ? parsed.map((f) => `[${f.engine}/${f.category}] ${f.malware} in ${f.file}`).join("\n") : "No malware/adware detected."
        }
      ]
    };
  };
}

// src/index.js
function registerSecurityTools(ctx) {
  return {
    sast_scan: makeSastScanHandler(ctx),
    dependency_audit: makeDependencyAuditHandler(ctx),
    av_scan: makeAvScanHandler(ctx)
  };
}
export {
  registerSecurityTools
};
