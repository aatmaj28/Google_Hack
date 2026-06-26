// Gemma backends. By default the pipeline uses GemmaFailover (vLLM first,
// then local Ollama), so a dropped tunnel mid-demo silently keeps using Gemma.
// Override with LLM_BACKEND (vllm | ollama | auto) — see logtriage/triage.py.
// All speak the OpenAI-compatible API -> openai-generic provider.
//
// IMPORTANT (Gemma gotcha): Gemma's chat template rejects a "system" role.
// The TriageIncident prompt is therefore emitted as a single *user* message
// (see {{ _.role("user") }} in triage.baml), which is safe for both backends.

// --- Failover chain (DEFAULT): try vLLM, fall back to local Ollama ----------
client<llm> GemmaFailover {
  provider fallback
  options {
    strategy [GemmaVLLM, GemmaOllama]
  }
}

// --- Backend 1: local / LAN Ollama -----------------------------------------
//   OLLAMA_BASE_URL  e.g. http://localhost:11434/v1  (or http://<lan-ip>:11434/v1)
//   GEMMA_MODEL      e.g. gemma2:9b / gemma4:12b / gemma2:2b
client<llm> GemmaOllama {
  provider "openai-generic"
  retry_policy Exponential
  options {
    base_url env.OLLAMA_BASE_URL
    model env.GEMMA_MODEL
    api_key "ollama"          // Ollama ignores this; openai-generic wants a value
    temperature 0.1
  }
}

// --- Backend 2: OpenAI-compatible vLLM (Gemma 3 12B IT) ---------------------
//   VLLM_BASE_URL  e.g. http://vllm-gemma3-12b:8001/v1  (internal Docker DNS)
//   VLLM_MODEL     google/gemma-3-12b-it
// No auth (vLLM has none) -> api_key "EMPTY". Context cap is 8192 tokens total,
// so we bound max_tokens; each call sends only ONE small candidate event.
client<llm> GemmaVLLM {
  provider "openai-generic"
  retry_policy Exponential
  options {
    base_url env.VLLM_BASE_URL
    model env.VLLM_MODEL
    api_key "EMPTY"
    temperature 0.2
    max_tokens 1024
  }
}

// One quick retry only, so failing over from a dead vLLM to Ollama is snappy.
retry_policy Exponential {
  max_retries 1
  strategy {
    type exponential_backoff
    options {
      multiplier 2
      max_delay_ms 2000
    }
  }
}
