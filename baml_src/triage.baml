// The validated output contract for one triaged incident.
// BAML's schema-aligned parsing coerces messy / fenced model output into this
// type and the @@assert blocks enforce the "syntactically perfect, webhook-ready"
// guarantee. Nothing here is specific to any single log format.

enum Severity {
  INFO
  WARNING
  ERROR
  CRITICAL
}

enum AnomalyType {
  SeverityError    @description("explicit ERROR / FATAL / CRITICAL log level")
  FailureKeyword   @description("message contains a failure keyword (exception, refused, timeout...)")
  RareEvent        @description("a statistically rare event template - unusual even if not an error")
  SequenceDeviation @description("an abnormal ordering / set of events within one session")
}

class CausalStep {
  step int
  event string @description("what happened at this step, in plain English")
}

class IncidentCard {
  service_name string @description("service/component that emitted this, inferred from the event; do not invent")
  timestamp string @description("ISO timestamp of the event, copied verbatim from the input")
  error_severity Severity
  anomaly_type AnomalyType
  root_cause string @description("one-sentence plain-English explanation of what actually broke")
  causal_chain CausalStep[] @description("ordered steps reconstructed from the session timeline; empty array if no timeline was given")
  suggested_remediation string @description("a concrete, actionable fix - not generic advice")
  confidence float @description("0.0 to 1.0 confidence in this diagnosis")

  @@assert(has_remediation, {{ this.suggested_remediation|length > 3 }})
  @@assert(valid_confidence, {{ this.confidence >= 0.0 and this.confidence <= 1.0 }})
}

function TriageIncident(event_json: string) -> IncidentCard {
  client GemmaOllama
  prompt #"
    {{ _.role("user") }}
    You are a production log-triage engine. You receive ONE pre-detected
    anomalous event (already extracted from a much larger log) as JSON, and you
    diagnose it into a structured incident card.

    Strict rules:
    - Use ONLY information present in the event below. Never invent a
      service_name, timestamp, or value that is not in the input.
    - Copy the timestamp verbatim from the input.
    - If an event_sequence / timeline is present, reconstruct causal_chain from
      it in order. If no timeline is present, return an empty causal_chain.
    - suggested_remediation must be a specific action an on-call engineer can
      take, grounded in this event - not generic advice.
    - Return ONLY the structured object. No prose, no markdown fences.

    {{ ctx.output_format }}

    Anomalous event:
    {{ event_json }}
  "#
}

test brute_force_ssh {
  functions [TriageIncident]
  args {
    event_json #"
      {"template_id":"E5","template":"Failed password for <*> from <IP> port <NUM>",
       "occurrences":42,"score":6.5,"signals":["severity:ERROR","keyword","rare:42"],
       "representative":{"timestamp":"2023-12-10T06:55:48","severity":"ERROR",
         "component":"sshd","message":"Failed password for root from 173.234.31.186 port 38926"},
       "session":{"key_type":"ip","key_value":"173.234.31.186",
         "event_sequence":["E5","E5","E5","E2"],
         "timeline":[{"message":"Failed password for root ..."},
                     {"message":"Accepted password for root ..."}]}}
    "#
  }
}
