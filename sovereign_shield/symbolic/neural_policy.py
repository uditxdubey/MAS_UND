"""
sovereign_shield/symbolic/neural_policy.py
Neural Advisor Policy — local LLM configuration.
Advisory only. Edit this file when upgrading the local model.
"""
from dataclasses import dataclass


@dataclass
class NeuralAdvisorPolicy:
    enabled: bool      = True
    model_path: str    = "./models/llama3-8b-instruct.Q4_K_M.gguf"
    n_threads: int     = 4      # M2 MacBook Air — optimal thread count
    max_tokens: int    = 16
    temperature: float = 0.0    # Always deterministic