#!/bin/bash

# Setup script for AutomaSploitService with OpenRouter
echo "Setting up AutomaSploitService with OpenRouter..."

# Check if OPENROUTER_API_KEY is already set
if [ -z "$OPENROUTER_API_KEY" ]; then
    echo "OPENROUTER_API_KEY environment variable is not set."
    echo "Please get your API key from https://openrouter.ai/keys"
    echo ""
    echo "You can set it by running:"
    echo "export OPENROUTER_API_KEY=your_api_key_here"
    echo ""
    echo "Or add it to your ~/.bashrc file:"
    echo "echo 'export OPENROUTER_API_KEY=your_api_key_here' >> ~/.bashrc"
    echo "source ~/.bashrc"
else
    echo "✓ OPENROUTER_API_KEY is set"
fi

echo ""
echo "To run the service:"
echo "cargo run"
