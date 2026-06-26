// LLM client definitions.
// Gemma 2 9B runs locally via Ollama's OpenAI-compatible endpoint.
// Make sure `ollama pull gemma2:9b` has been run and `ollama serve` is up.

client<llm> Gemma9B {
  provider "openai-generic"
  options {
    base_url "http://localhost:11434/v1"
    api_key "ollama"
    model "gemma2:9b"
    temperature 0.1
  }
}
