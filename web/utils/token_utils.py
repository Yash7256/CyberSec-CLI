from typing import List

GROQ_MODEL_LIMITS = {
    "llama-3.1-8b-instant": 128000,
    "llama-3.1-70b-versatile": 128000,
    "llama3-8b-8192": 8192,
    "llama3-70b-8192": 8192,
    "mixtral-8x7b-32768": 32768,
    "gemma-7b-it": 8192,
    "gemma2-9b-it": 8192,
}

RESPONSE_TOKEN_RESERVE = 1500  # Reserve for AI response
SYSTEM_PROMPT_TOKENS = 400   # Approximate system prompt size
HISTORY_TOKENS_RESERVE = 2000  # Reserve for conversation history


class TokenCounter:
    """Token counter with tiktoken support and graceful fallback."""
    _encoder = None
    _use_tiktoken = False
    _initialized = False

    @classmethod
    def initialize(cls):
        """Lazy initialization - called on first use."""
        if cls._initialized:
            return
        cls._initialized = True
        try:
            import tiktoken
            cls._encoder = tiktoken.get_encoding("cl100k_base")
            cls._use_tiktoken = True
            print("✓ TokenCounter: using tiktoken for accurate counting")
        except ImportError:
            cls._use_tiktoken = False
            print("⚠ TokenCounter: tiktoken not installed, using approximation (4 chars/token)")

    @classmethod
    def count(cls, text: str) -> int:
        """Count tokens in text using tiktoken or approximation."""
        if cls._encoder is None:
            cls.initialize()
        if cls._use_tiktoken:
            return len(cls._encoder.encode(text))
        return len(text) // 4

    @classmethod
    def count_messages(cls, messages: List[dict]) -> int:
        """Count tokens across entire message array."""
        if cls._encoder is None:
            cls.initialize()
        total = 0
        for msg in messages:
            total += 4  # message overhead (role, delimiters)
            total += cls.count(msg.get("content", ""))
            total += cls.count(msg.get("role", ""))
        total += 2  # conversation overhead
        return total

    @classmethod
    def is_accurate(cls) -> bool:
        """Return True if using tiktoken (accurate), False if using approximation."""
        if cls._encoder is None:
            cls.initialize()
        return cls._use_tiktoken


def get_context_token_budget(model: str) -> int:
    limit = GROQ_MODEL_LIMITS.get(model, 8192)
    budget = limit - RESPONSE_TOKEN_RESERVE - SYSTEM_PROMPT_TOKENS - HISTORY_TOKENS_RESERVE
    return max(500, budget)


def count_tokens(text: str) -> int:
    """Legacy function - now delegates to TokenCounter."""
    return TokenCounter.count(text)


def truncate_to_token_budget(text: str, budget: int) -> tuple[str, bool]:
    """Returns (truncated_text, was_truncated)."""
    current_tokens = TokenCounter.count(text)
    if current_tokens <= budget:
        return text, False
    
    # Binary search for the right character count
    # Start with rough estimate: budget * 3.5 chars
    target_chars = int(budget * 3.5)
    truncated = text[:target_chars]
    
    # Fine-tune: ensure we're under budget
    while TokenCounter.count(truncated) > budget and len(truncated) > 100:
        truncated = truncated[:int(len(truncated) * 0.9)]
    
    return truncated + "\n\n[context truncated — token limit reached]", True
