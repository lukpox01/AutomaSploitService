# AutomaSploitService with OpenRouter Integration

This service has been modified to use OpenRouter API instead of local Ollama for AI interactions.

## Changes Made

1. **Replaced Ollama with OpenRouter**: The `ask_openai` function now makes HTTP requests to OpenRouter's API
2. **Added OpenRouter API structures**: New structs for handling OpenRouter requests and responses
3. **Environment variable configuration**: API key is now read from `OPENROUTER_API_KEY` environment variable
4. **HTTP client**: Using reqwest HTTP client instead of Ollama client

## Setup Instructions

### 1. Install Rust (if not already installed)
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
```

### 2. Get OpenRouter API Key
1. Visit https://openrouter.ai/keys
2. Create an account and generate an API key
3. Set the environment variable:
```bash
export OPENROUTER_API_KEY=your_api_key_here
```

### 3. Run the Service
```bash
# Build and run
cargo run

# Or just build
cargo build
```

## API Usage

The `/ask` endpoint remains the same:

```bash
curl -X POST http://127.0.0.1:8084/ask \
  -H "Content-Type: application/json" \
  -d '{"question": "What is penetration testing?"}'
```

## Model Configuration

The service is currently configured to use `deepseek/deepseek-r1` model from OpenRouter. You can modify this in the `ask_openai` function by changing the `model` field in the `OpenRouterRequest`.

Available models can be found at: https://openrouter.ai/models

## Environment Variables

- `OPENROUTER_API_KEY`: Required - Your OpenRouter API key
- `RUST_LOG`: Optional - Set logging level (default: info)

## Dependencies

The following dependencies are used:
- `reqwest`: For HTTP requests to OpenRouter API
- `actix-web`: Web framework
- `serde`: JSON serialization/deserialization
- `tokio`: Async runtime

## Error Handling

The service includes comprehensive error handling for:
- Missing API key
- OpenRouter API errors
- Network connectivity issues
- JSON parsing errors
