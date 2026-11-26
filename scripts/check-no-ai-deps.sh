#!/usr/bin/env bash
set -euo pipefail

BANNED_PATTERN='openai|anthropic|google/generative-ai|@google/genai|tensorflow|torch|pytorch|onnx|langchain|llamaindex|transformers|huggingface|scikit-learn|ollama|vllm|chromadb|pinecone|qdrant|weaviate'

FILES_TO_CHECK=()
if [ -f "backend/go.mod" ]; then
  FILES_TO_CHECK+=("backend/go.mod")
fi
if [ -f "frontend/package.json" ]; then
  FILES_TO_CHECK+=("frontend/package.json")
fi
if [ -f "frontend/package-lock.json" ]; then
  FILES_TO_CHECK+=("frontend/package-lock.json")
fi

if [ "${#FILES_TO_CHECK[@]}" -eq 0 ]; then
  echo "No dependency manifests found to scan."
  exit 0
fi

FOUND=0
for manifest in "${FILES_TO_CHECK[@]}"; do
  if grep -Ein "$BANNED_PATTERN" "$manifest"; then
    echo "ERROR: Prohibited AI/ML dependency found in $manifest" >&2
    FOUND=1
  fi
done

if [ "$FOUND" -ne 0 ]; then
  exit 1
fi

echo "Zero AI/ML dependencies verified across: ${FILES_TO_CHECK[*]}"
