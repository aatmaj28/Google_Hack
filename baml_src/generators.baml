// Tells `baml-cli generate` what client code to produce.
generator python {
  output_type "python/pydantic"
  output_dir "../"
  version "0.223.0"
  default_client_mode "sync"
}
