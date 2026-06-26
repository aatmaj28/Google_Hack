// LLM client definitions.
// Gemma runs locally via Ollama's OpenAI-compatible endpoint.
// Make sure `ollama serve` is up and the model below is pulled.

client<llm> Gemma9B {
  provider "openai-generic"
  options {
    base_url "http://localhost:11434/v1"
    api_key "ollama"
    model "gemma4:latest"
    temperature 0.1
  }
}
