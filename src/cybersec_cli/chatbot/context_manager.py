"""
Context Manager for the Cybersec CLI.
Manages session state, tool execution, and context preservation.
"""

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from pydantic import BaseModel, Field

from ..utils.logger import setup_logger
from .ai_engine import AIEngine
from .command_parser import CommandParser
from .conversation import Conversation

logger = setup_logger(__name__)


@dataclass
class ToolResult:
    """Represents the result of a tool execution."""

    success: bool
    output: Any
    error: Optional[str] = None
    execution_time: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


class SessionState(BaseModel):
    """Represents the state of a user session."""

    session_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_active: datetime = Field(default_factory=datetime.utcnow)
    context: Dict[str, Any] = Field(default_factory=dict)
    active_tools: List[str] = Field(default_factory=list)
    preferences: Dict[str, Any] = Field(default_factory=dict)

    def update_activity(self):
        """Update the last active timestamp."""
        self.last_active = datetime.utcnow()

    def to_dict(self) -> Dict:
        """Convert session state to dictionary."""
        return {
            "session_id": self.session_id,
            "created_at": self.created_at.isoformat(),
            "last_active": self.last_active.isoformat(),
            "context": self.context,
            "active_tools": self.active_tools,
            "preferences": self.preferences,
        }

    @classmethod
    def from_dict(cls, data: Dict) -> "SessionState":
        """Create session state from dictionary."""
        return cls(
            session_id=data.get("session_id", str(uuid.uuid4())),
            created_at=datetime.fromisoformat(data.get("created_at")),
            last_active=datetime.fromisoformat(data.get("last_active")),
            context=data.get("context", {}),
            active_tools=data.get("active_tools", []),
            preferences=data.get("preferences", {}),
        )


class ContextManager:
    """
    Manages the context and state of a Cybersec CLI session.
    Handles tool registration, execution, and state persistence.
    """

    def __init__(self, data_dir: Path = None):
        self.data_dir = data_dir or Path.home() / ".cybersec"
        self.sessions: Dict[str, SessionState] = {}
        self.conversations: Dict[str, Conversation] = {}
        self.tools: Dict[str, dict] = {}
        self.ai_engine = AIEngine()
        self.command_parser = CommandParser()
        self._setup_data_dir()

    def _setup_data_dir(self) -> None:
        """Ensure the data directory exists."""
        self.data_dir.mkdir(parents=True, exist_ok=True)
        (self.data_dir / "sessions").mkdir(exist_ok=True)
        (self.data_dir / "conversations").mkdir(exist_ok=True)

    def register_tool(
        self, name: str, func: Callable, description: str, parameters: Dict[str, Any]
    ) -> None:
        """Register a new tool that can be called by the AI."""
        self.tools[name] = {
            "function": func,
            "description": description,
            "parameters": parameters,
        }
        logger.info(f"Registered tool: {name}")

    async def create_session(self, session_id: str = None) -> SessionState:
        """Create a new session or retrieve an existing one."""
        session_id = session_id or str(uuid.uuid4())

        if session_id in self.sessions:
            self.sessions[session_id].update_activity()
            return self.sessions[session_id]

        # Try to load from disk if it exists
        session_file = self.data_dir / "sessions" / f"{session_id}.json"
        if session_file.exists():
            try:
                with open(session_file, "r") as f:
                    session_data = json.load(f)
                session = SessionState.from_dict(session_data)
                self.sessions[session_id] = session
                logger.info(f"Loaded existing session: {session_id}")
                return session
            except Exception as e:
                logger.error(f"Error loading session {session_id}: {e}")

        # Create a new session
        session = SessionState(session_id=session_id)
        self.sessions[session_id] = session

        # Create a new conversation
        self.conversations[session_id] = Conversation()

        logger.info(f"Created new session: {session_id}")
        return session

    async def get_conversation(self, session_id: str) -> Optional[Conversation]:
        """Get the conversation for a session."""
        if session_id not in self.conversations:
            await self.create_session(session_id)
        return self.conversations.get(session_id)

    async def save_session(self, session_id: str) -> bool:
        """Save session state to disk."""
        if session_id not in self.sessions:
            logger.warning(f"Cannot save non-existent session: {session_id}")
            return False

        session = self.sessions[session_id]
        session_file = self.data_dir / "sessions" / f"{session_id}.json"

        try:
            with open(session_file, "w") as f:
                json.dump(session.to_dict(), f, indent=2)

            # Save conversation if it exists
            if session_id in self.conversations:
                conv_file = self.data_dir / "conversations" / f"{session_id}.json"
                self.conversations[session_id].save_to_file(conv_file)

            logger.debug(f"Saved session: {session_id}")
            return True
        except Exception as e:
            logger.error(f"Error saving session {session_id}: {e}")
            return False

    async def execute_tool(
        self, tool_name: str, parameters: Dict[str, Any], session_id: str
    ) -> ToolResult:
        """Execute a registered tool with the given parameters."""
        if tool_name not in self.tools:
            return ToolResult(
                success=False, output=None, error=f"Tool not found: {tool_name}"
            )

        tool = self.tools[tool_name]
        session = await self.create_session(session_id)
        session.update_activity()

        # Validate parameters
        missing_params = [
            p for p in tool["parameters"].get("required", []) if p not in parameters
        ]

        if missing_params:
            return ToolResult(
                success=False,
                output=None,
                error=f"Missing required parameters: {', '.join(missing_params)}",
            )

        # Execute the tool
        start_time = datetime.utcnow()
        try:
            result = await tool["function"](**parameters)
            execution_time = (datetime.utcnow() - start_time).total_seconds()

            return ToolResult(
                success=True,
                output=result,
                execution_time=execution_time,
                metadata={"tool": tool_name},
            )

        except Exception as e:
            logger.exception(f"Error executing tool {tool_name}")
            return ToolResult(
                success=False,
                output=None,
                error=str(e),
                execution_time=(datetime.utcnow() - start_time).total_seconds(),
                metadata={"tool": tool_name},
            )

    async def process_message(self, message: str, session_id: str) -> str:
        """Process a user message and return a response."""
        session = await self.create_session(session_id)
        conversation = await self.get_conversation(session_id)

        if not conversation:
            return "Error: Could not create or load conversation."

        # Add user message to conversation
        conversation.add_message("user", message)

        # Parse the command and wire it into session context for downstream handling
        parsed_command = self.command_parser.parse(message)
        session.context["last_parsed_command"] = parsed_command.to_dict()

        # Short-circuit simple control commands
        if parsed_command.action == "clear":
            response_text = "Screen cleared."
            conversation.add_message("assistant", response_text)
            await self.save_session(session_id)
            return response_text
        if parsed_command.action == "exit":
            response_text = "Goodbye."
            conversation.add_message("assistant", response_text)
            await self.save_session(session_id)
            return response_text

        # Provide parsed command context to the AI when actionable
        if parsed_command.action not in {"query", "unknown"}:
            conversation.add_message(
                "system",
                f"Parsed command: {json.dumps(parsed_command.to_dict())}",
            )

        try:
            # Get AI response
            messages = conversation.get_messages()
            response = await self.ai_engine.generate_response(
                messages=messages, tools=self._get_tools_spec()
            )

            # Handle tool calls if any
            if response.tool_calls:
                tool_responses = []

                for tool_call in response.tool_calls:
                    tool_name = tool_call["function"]["name"]
                    try:
                        # Parse arguments
                        args = json.loads(tool_call["function"]["arguments"])

                        # Execute tool
                        result = await self.execute_tool(
                            tool_name=tool_name, parameters=args, session_id=session_id
                        )

                        # Add tool response to conversation
                        tool_responses.append(
                            {
                                "tool_call_id": tool_call["id"],
                                "role": "tool",
                                "name": tool_name,
                                "content": json.dumps(
                                    {
                                        "success": result.success,
                                        "output": result.output,
                                        "error": result.error,
                                    }
                                ),
                            }
                        )

                    except Exception as e:
                        logger.error(f"Error handling tool call {tool_name}: {e}")
                        tool_responses.append(
                            {
                                "tool_call_id": tool_call["id"],
                                "role": "tool",
                                "name": tool_name,
                                "content": json.dumps(
                                    {
                                        "success": False,
                                        "error": f"Error executing tool: {str(e)}",
                                    }
                                ),
                            }
                        )

                # Get final response with tool results
                final_response = await self.ai_engine.generate_response(
                    messages=messages
                    + [
                        {
                            "role": "assistant",
                            "content": None,
                            "tool_calls": response.tool_calls,
                        }
                    ]
                    + tool_responses,
                    tools=self._get_tools_spec(),
                )

                response_text = final_response.content
            else:
                response_text = response.content

            # Add assistant response to conversation
            conversation.add_message("assistant", response_text)

            # Save session
            await self.save_session(session_id)

            return response_text

        except Exception as e:
            logger.exception("Error processing message")
            return f"Sorry, I encountered an error: {str(e)}"

    def _get_tools_spec(self) -> List[Dict]:
        """Get the tools specification for the AI."""
        tools = []

        for name, tool in self.tools.items():
            tools.append(
                {
                    "type": "function",
                    "function": {
                        "name": name,
                        "description": tool["description"],
                        "parameters": tool["parameters"],
                    },
                }
            )

        return tools

    async def close(self):
        """Clean up resources."""
        # Save all active sessions
        for session_id in list(self.sessions.keys()):
            await self.save_session(session_id)

        # Close AI engine if needed
        if hasattr(self.ai_engine, "close"):
            await self.ai_engine.close()


# Singleton instance
context_manager = ContextManager()


# Helper function to get the context manager
def get_context_manager() -> ContextManager:
    """Get the global context manager instance."""
    return context_manager
