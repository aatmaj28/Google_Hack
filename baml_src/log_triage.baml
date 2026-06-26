enum ErrorSeverity {
  CRITICAL @description("System crash, data loss, or complete service outage")
  HIGH     @description("Service significantly degraded or repeated failures")
  MEDIUM   @description("Recoverable error or single isolated failure")
  LOW      @description("Warning or potential future problem, not yet impactful")
}

class LogAnomaly {
  service_name string          @description("The service, component, daemon, or process that generated the anomaly (e.g., sshd, dfs.DataNode, mod_jk, nova.compute)")
  timestamp string             @description("Timestamp from the log line. Normalize to ISO 8601 (YYYY-MM-DDTHH:MM:SS) where possible, otherwise preserve as-is")
  error_severity ErrorSeverity
  raw_log_line string          @description("The exact verbatim log line(s) that represent the anomaly, including any stack trace lines directly associated")
  suggested_remediation string @description("Specific, actionable remediation steps an SRE should take to resolve this issue")
}

class TriageResult {
  anomalies LogAnomaly[]
  has_critical_issues bool     @description("True if any anomaly has CRITICAL severity")
  summary string               @description("One sentence summary of the most significant issue found, or 'No anomalies detected' if anomalies is empty")
}

function TriageLogs(log_chunk: string) -> TriageResult {
  client GemmaLocal
  prompt #"
    {{ _.role("system") }}
    You are a senior SRE (Site Reliability Engineer) analyzing raw production system logs.

    Your task:
    1. Ignore all benign INFO, DEBUG, TRACE, and NOTICE lines that indicate normal operations
    2. Identify every ERROR, FATAL, CRITICAL, WARNING, exception, crash, failure, or timeout event
    3. For each anomaly found, extract precisely structured data
    4. If no real anomalies exist in the chunk, return an empty anomalies array

    Rules:
    - Only report genuine problems, not routine operational messages
    - A WARNING about repeated failures is HIGH severity; a single transient warning is LOW
    - Authentication failures that are isolated are MEDIUM; brute-force patterns are HIGH
    - Hardware errors (memory, CPU) are always CRITICAL or HIGH
    - Be specific in remediation steps — name the exact service, config file, or command

    {{ _.role("user") }}
    Analyze the following log lines and extract all anomalies:

    <log_chunk>
    {{ log_chunk }}
    </log_chunk>

    {{ ctx.output_format }}
  "#
}
