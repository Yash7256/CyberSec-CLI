"""Cybersec CLI Chatbot Module

This module provides the core chatbot functionality for the Cybersec CLI,
including AI integration, conversation management, and command parsing.
"""

from .ai_engine import AIEngine, AIResponse
from .command_parser import Command, CommandParser
from .context_manager import (
    ContextManager,
    SessionState,
    ToolResult,
    get_context_manager,
)
from .conversation import Conversation, Message

# Create a default context manager instance
context_manager = get_context_manager()

__all__ = [
    "AIEngine",
    "AIResponse",
    "Conversation",
    "Message",
    "CommandParser",
    "Command",
    "ContextManager",
    "SessionState",
    "ToolResult",
    "context_manager",
    "get_context_manager",
]
