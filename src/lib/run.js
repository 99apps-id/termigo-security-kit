// Shared helper: run a shell command through the Termigo backend.
export async function runShell(ctx, command, { cwd, timeoutSecs } = {}) {
  return ctx.invoke("shell_run_command", {
    command,
    cwd: cwd || undefined,
    timeout_secs: timeoutSecs || undefined,
  });
}

// Refuse empty / blank input before it reaches the shell.
export function requireValue(value, label) {
  const trimmed = value == null ? "" : String(value).trim();
  if (!trimmed) {
    throw new Error(`${label} cannot be empty`);
  }
  return trimmed;
}

// Read the extension's declared settings.
export async function readSetting(ctx, key, fallback = "") {
  try {
    const v = await ctx.settings.get(key);
    return v == null ? fallback : String(v);
  } catch {
    return fallback;
  }
}

// Persist a tool's output as a Markdown report.
export async function saveReport(ctx, { tool, target, command, output, severity = "info" }) {
  try {
    const workingDir = (await readSetting(ctx, "security.workingDir")).trim().replace(/[\\/]+$/, "");
    const rel = `${(workingDir || "security-reports").replace(/[\\/]+$/, "")}/${tool}-${(target || "unknown").replace(/[^\w.-]+/g, "_")}-${new Date().toISOString().replace(/[:.]/g, "-")}.md`;
    const text = output && output.stdout ? output.stdout : String(output || "");
    const content = [
      `# ${tool} report`,
      "",
      `- **Tool:** ${tool}`,
      `- **Target:** ${target || "n/a"}`,
      `- **Command:** \`${command || ""}\``,
      `- **Severity:** ${severity}`,
      `- **Time:** ${new Date().toISOString()}`,
      "",
      "## Output",
      "",
      "```",
      String(text).slice(0, 20000),
      "```",
      "",
    ].join("\n");
    await ctx.invoke("fs_write_file", { path: rel, content });
    return rel;
  } catch (e) {
    try {
      ctx.logger.warn(`report save failed: ${String(e)}`);
    } catch {
      // ignore
    }
    return null;
  }
}

// Wrap a command result so the agent gets a structured finding.
export function finding(ctx, { tool, target, command, output, severity = "info" }) {
  const text = output && output.stdout ? output.stdout : String(output || "");
  const failed = !output || typeof output !== "object" || output.timed_out === true || (output.exit_code !== undefined && output.exit_code !== 0);
  if (failed) {
    return {
      tool,
      target,
      command,
      output,
      error: `Command failed${output && typeof output === "object" && output.timed_out ? " (timed out)" : output && typeof output === "object" && output.exit_code !== undefined ? ` with exit code ${output.exit_code}` : ""}`,
      findings: [
        {
          tool,
          target,
          severity: "error",
          summary: firstLine(text) || `Command failed`,
          evidence: clip(text, 6000),
        },
      ],
    };
  }
  void saveReport(ctx, { tool, target, command, output, severity }).catch(() => {});
  return {
    tool,
    target,
    command,
    output,
    findings: [
      {
        tool,
        target,
        severity,
        summary: firstLine(text),
        evidence: clip(text, 6000),
      },
    ],
  };
}

function firstLine(text) {
  const line = String(text || "").split("\n").find((l) => l.trim());
  return line ? line.trim().slice(0, 200) : "";
}

function clip(text, n) {
  return String(text || "").slice(0, n);
}

export async function toolOptions(ctx, overrides = {}) {
  let timeoutSecs = 300;
  try {
    const t = await ctx.settings.get("security.shellTimeoutSecs");
    if (typeof t === "number" && t > 0) timeoutSecs = t;
  } catch {
    // unset -> default
  }
  return {
    timeoutSecs: overrides.timeoutSecs ?? timeoutSecs,
  };
}

