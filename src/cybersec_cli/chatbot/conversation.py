"""
Conversation management for the Cybersec CLI chatbot.
Handles conversation history and context management.
"""

import json
from collections import deque
from datetime import datetime
from pathlib import Path
from typing import Deque, Dict, List

from pydantic import BaseModel, Field


class Message(BaseModel):
    """Represents a message in the conversation."""

    role: str  # 'system', 'user', 'assistant', or 'tool'
    content: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    metadata: Dict = Field(default_factory=dict)

    def to_dict(self) -> Dict:
        """Convert message to dictionary for serialization."""
        return {
            "role": self.role,
            "content": self.content,
            "timestamp": self.timestamp.isoformat(),
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict) -> "Message":
        """Create a message from a dictionary."""
        return cls(
            role=data["role"],
            content=data["content"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
            metadata=data.get("metadata", {}),
        )


class Conversation:
    """Manages a conversation with context and history."""

    def __init__(self, max_history: int = 20):
        self.messages: Deque[Message] = deque(maxlen=max_history)
        self.context: Dict = {}

    def add_message(self, role: str, content: str, **metadata) -> None:
        """Add a message to the conversation."""
        self.messages.append(
            Message(role=role, content=content, metadata=metadata or {})
        )

    def get_messages(self, include_metadata: bool = False) -> List[Dict]:
        """Get conversation messages in a format suitable for the AI API."""
        return [
            {
                "role": msg.role,
                "content": msg.content,
                **(msg.metadata if include_metadata else {}),
            }
            for msg in self.messages
        ]

    def get_recent_messages(self, count: int = 5) -> List[Message]:
        """Get the most recent messages."""
        return list(self.messages)[-count:]

    def clear(self) -> None:
        """Clear the conversation history."""
        self.messages.clear()
        self.context.clear()

    def save_to_file(self, file_path: Path) -> None:
        """Save conversation to a file."""
        data = {
            "messages": [msg.to_dict() for msg in self.messages],
            "context": self.context,
            "metadata": {
                "created_at": datetime.utcnow().isoformat(),
                "message_count": len(self.messages),
            },
        }

        file_path.parent.mkdir(parents=True, exist_ok=True)
        with open(file_path, "w") as f:
            json.dump(data, f, indent=2)

    @classmethod
    def load_from_file(cls, file_path: Path) -> "Conversation":
        """Load conversation from a file."""
        if not file_path.exists():
            raise FileNotFoundError(f"Conversation file not found: {file_path}")

        with open(file_path, "r") as f:
            data = json.load(f)

        conv = cls()
        conv.messages = deque(
            [Message.from_dict(msg_data) for msg_data in data.get("messages", [])],
            maxlen=conv.messages.maxlen,
        )

        conv.context = data.get("context", {})
        return conv

    def __len__(self) -> int:
        """Get the number of messages in the conversation."""
        return len(self.messages)
