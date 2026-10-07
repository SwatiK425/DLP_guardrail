---
title: DLP Guardrail
emoji: 🛡️
colorFrom: blue
colorTo: yellow
sdk: gradio
sdk_version: 4.44.1
app_file: app.py
pinned: false
license: mit
---

# Intent-Based DLP Guardrail

A 4-layer guardrail that catches jailbreaks, prompt injections, and data-exfiltration requests before they reach your LLM.

## Layers

1. **Layer 0** - Obfuscation decoder (encoding, invisible chars, leetspeak, LaTeX)
2. **Layer 1** - Behavioral intent (malicious intent combinations)
3. **Layer 2** - Semantic embeddings (similarity to known attacks)
4. **Layer 3** - Transformer classifier (deBERTa injection detection)
5. **LLM Judge** - BYOK final arbiter for uncertain cases

## Usage

1. Attach your LLM API key (Google, Anthropic, OpenAI, OpenRouter, OpenCode Zen)
2. Enter a prompt to test
3. See detailed layer breakdown and verdict

## API

The Gradio API is available at `/api/predict` for programmatic access.
