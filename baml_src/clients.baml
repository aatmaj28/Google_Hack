client<llm> GemmaLocal {
  provider openai-generic
  options {
    base_url "http://localhost:11434/v1"
    model "gemma4:12b"
    api_key "ollama"
    temperature 0.1
    max_tokens 4096
  }
}
