// Log triage: input is a multi-line burst already prefiltered as "interesting".
// Output is a single LogAnomaly or null if the burst turns out to be benign.

class LogAnomaly {
  service_name string @description(#"
    The service, daemon, or component that emitted the failing line
    (e.g. "dfs.DataNode", "sshd", "QuorumCnxManager"). Copy from the line.
  "#)

  timestamp string @description(#"
    The timestamp of the failing line, in ISO 8601 if derivable
    (YYYY-MM-DDTHH:MM:SS), otherwise verbatim from the log line.
  "#)

  error_severity string @description(#"
    One of: INFO, WARN, ERROR, FATAL, CRITICAL.
    Pick the most accurate severity for the failure, not the literal label
    if the literal label understates the impact.
  "#)

  suggested_remediation string @description(#"
    ONE concrete operator action to try first. Specific, not generic.
    Example: "Check disk space on the DataNode's mount", not "investigate".
  "#)

  evidence_line string @description(#"
    The exact failing log line, copied verbatim from the burst.
  "#)
}

function TriageBurst(burst: string, format_hint: string) -> LogAnomaly? {
  client Gemma9B
  prompt #"
    You are a log triage assistant for production systems.

    A burst of related log lines is shown below. The lines are from a
    {{ format_hint }} log. Your job:

    1. Identify the SINGLE line in the burst that represents the actual
       failure or anomaly. Stack traces and follow-on messages should
       point you to the original error line.
    2. If the burst is benign (only routine INFO messages, expected
       lifecycle events, no real failure), return null.
    3. Otherwise, fill out a LogAnomaly. Be precise:
       - service_name comes from the line itself.
       - timestamp comes from the line itself.
       - suggested_remediation must be a concrete first action an operator
         would take, not generic advice.

    LOG BURST:
    ---
    {{ burst }}
    ---

    {{ ctx.output_format }}
  "#
}
