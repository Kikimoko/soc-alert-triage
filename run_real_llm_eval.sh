#!/usr/bin/env bash
# One-command real-LLM evaluation with Ollama (runs locally; nothing leaves your machine).
# Usage: bash run_real_llm_eval.sh [model] [n_alerts]     e.g. bash run_real_llm_eval.sh llama3.1:8b 300
set -e
MODEL=${1:-llama3.1:8b}; N=${2:-300}
command -v ollama >/dev/null || { echo "Install Ollama first: https://ollama.com/download"; exit 1; }
curl -s localhost:11434 >/dev/null || { echo "Start it: ollama serve (in another terminal)"; exit 1; }
ollama pull "$MODEL"
[ -f data/UNSW_NB15_testing-set.csv ] || bash src/download_data.sh
echo "== prompt v1 (plain instructions)"; python src/copilot_eval.py --backend "ollama:$MODEL" --n "$N" --prompt v1
echo "== prompt v2 (hardened prompt + example)"; python src/copilot_eval.py --backend "ollama:$MODEL" --n "$N" --prompt v2
echo "Compare the two result files: hallucination rate, action recall, injection success (with/without guardrail), latency."
echo "Report BOTH in the README - including numbers you don't like."
