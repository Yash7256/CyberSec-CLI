"""
AI Engine for the Cybersec CLI chatbot.
Handles communication with AI models and response generation.
OpenAI API is OPTIONAL - fallback to rule-based analysis if API key not provided.
"""

import json
import logging
from typing import AsyncGenerator, Dict, List, Optional

try:
    import aiohttp

    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False

from pydantic import BaseModel, Field

from cybersec_cli.config import settings
from .command_parser import CommandParser

logger = logging.getLogger(__name__)


class AIMessage(BaseModel):
    """Represents a message in the conversation."""

    role: str  # 'system', 'user', 'assistant', or 'tool'
    content: str
    name: Optional[str] = None
    tool_calls: Optional[List[Dict]] = None
    tool_call_id: Optional[str] = None


class AIResponse(BaseModel):
    """Structured response from the AI."""

    content: str
    tool_calls: List[Dict] = Field(default_factory=list)
    model: str
    usage: Optional[Dict] = None


class AIEngine:
    """Handles communication with AI models.

    Falls back to rule-based analysis if no API key is provided.
    """

    def __init__(self, api_key: str = None, model: str = None):
        self.api_key = api_key or settings.ai.api_key
        self.model = model or settings.ai.model
        self.base_url = "https://api.openai.com/v1"
        self.session = None
        self.use_api = self.api_key is not None and AIOHTTP_AVAILABLE

        if not self.use_api:
            logger.info(
                "OpenAI API not configured. Using fallback rule-based analysis."
            )

    async def __aenter__(self):
        if self.use_api:
            self.session = aiohttp.ClientSession()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    async def generate_response(
        self,
        messages: List[Dict],
        tools: Optional[List[Dict]] = None,
        temperature: float = None,
        max_tokens: int = None,
    ) -> AIResponse:
        """Generate a response from the AI model or fallback to rule-based analysis."""
        if self.use_api:
            api_response = await self._generate_api_response(
                messages, tools, temperature, max_tokens
            )
            if api_response is None:
                return self._generate_fallback_response(messages)
            return api_response
        else:
            return self._generate_fallback_response(messages)

    async def _generate_api_response(
        self,
        messages: List[Dict],
        tools: Optional[List[Dict]] = None,
        temperature: float = None,
        max_tokens: int = None,
    ) -> Optional[AIResponse]:
        """Generate response using OpenAI API."""
        if not self.api_key:
            raise ValueError("API key is required")

        if not self.session:
            self.session = aiohttp.ClientSession()

        temperature = temperature or settings.ai.temperature
        max_tokens = max_tokens or settings.ai.max_tokens

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }
        safe_headers = {
            k: v
            for k, v in headers.items()
            if "key" not in k.lower()
            and "auth" not in k.lower()
            and "secret" not in k.lower()
        }

        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }

        if tools:
            payload["tools"] = tools

        try:
            async with self.session.post(
                f"{self.base_url}/chat/completions", headers=headers, json=payload
            ) as response:
                response.raise_for_status()
                data = await response.json()

                # Validate response structure
                if not data or not data.get("choices"):
                    logger.error("Empty or invalid response from AI API")
                    return None

                choice = data["choices"][0].get("message", {})
                return AIResponse(
                    content=choice.get("content", ""),
                    tool_calls=choice.get("tool_calls", []),
                    model=data["model"],
                    usage=data.get("usage"),
                )

        except Exception as e:
            # Log without exposing sensitive details
            logger.error("Error generating AI response (details hidden for security)")
            logger.debug("AI request headers (scrubbed): %s", safe_headers)
            logger.info("Falling back to rule-based analysis")
            return self._generate_fallback_response(messages)

    def _generate_fallback_response(self, messages: List[Dict]) -> AIResponse:
        """Generate response using rule-based analysis (no API required)."""
        # Extract the user's message
        user_message = ""
        for msg in reversed(messages):
            if msg.get("role") == "user":
                user_message = msg.get("content", "")
                break

        # Rule-based analysis
        content = self._analyze_message(user_message)

        return AIResponse(
            content=content, tool_calls=[], model="fallback-analysis", usage=None
        )

    def _analyze_message(self, message: str) -> str:
        """Analyze a message and return rule-based response."""
        message_lower = message.lower()

        # Port security analysis
        if "port" in message_lower:
            return self._analyze_port_security(message)

        # Service security analysis
        if any(
            service in message_lower
            for service in ["ssh", "http", "ftp", "mysql", "postgres", "redis"]
        ):
            return self._analyze_service_security(message)

        # General security question
        if any(
            keyword in message_lower
            for keyword in ["secure", "risk", "vulnerability", "safe", "threat"]
        ):
            return self._generate_security_advice(message)

        # Default response
        return self._generate_default_response(message)

    def _analyze_port_security(self, message: str) -> str:
        """Provide security analysis for ports."""
        response = "🔍 Port Security Analysis:\n\n"

        port_patterns = {
            "22": (
                "SSH",
                "Remote access",
                "Critical - Control access with firewall rules",
            ),
            "80": ("HTTP", "Web server", "Use HTTPS instead (port 443)"),
            "443": (
                "HTTPS",
                "Secure web",
                "Generally secure if TLS is properly configured",
            ),
            "3306": (
                "MySQL",
                "Database",
                "CRITICAL - Never expose database to internet",
            ),
            "5432": (
                "PostgreSQL",
                "Database",
                "CRITICAL - Keep on internal network only",
            ),
            "6379": ("Redis", "Cache", "CRITICAL - Expose only to internal services"),
            "27017": ("MongoDB", "Database", "CRITICAL - Restrict to private network"),
            "8080": (
                "HTTP Alt",
                "Web proxy/app",
                "Verify if necessary, consider firewall",
            ),
        }

        for port, (service, description, recommendation) in port_patterns.items():
            if port in message:
                response += f"Port {port} ({service}):\n"
                response += f"  • Service: {description}\n"
                response += f"  • Recommendation: {recommendation}\n\n"

        response += "General Port Security Best Practices:\n"
        response += "  1. Close unnecessary ports\n"
        response += "  2. Use firewalls to restrict access\n"
        response += "  3. Run services on non-standard ports\n"
        response += "  4. Implement VPN for remote access\n"
        response += "  5. Monitor for suspicious connections\n"

        return response

    def _analyze_service_security(self, message: str) -> str:
        """Provide security analysis for services."""
        response = "🛡️ Service Security Analysis:\n\n"

        services = {
            "ssh": {
                "description": "Secure Shell (Remote Access)",
                "risks": [
                    "Brute force attacks",
                    "Weak authentication",
                    "Exposed to internet",
                ],
                "recommendations": [
                    "Use key-based auth",
                    "Disable root login",
                    "Change default port",
                    "Fail2ban",
                ],
            },
            "http": {
                "description": "Hypertext Transfer Protocol",
                "risks": [
                    "Unencrypted transmission",
                    "Man-in-the-middle attacks",
                    "Data exposure",
                ],
                "recommendations": [
                    "Use HTTPS instead",
                    "Redirect HTTP to HTTPS",
                    "Enable HSTS header",
                ],
            },
            "mysql": {
                "description": "MySQL Database",
                "risks": ["Database exposure", "SQL injection", "Unauthorized access"],
                "recommendations": [
                    "Restrict to private network",
                    "Strong passwords",
                    "Use firewall",
                    "Regular backups",
                ],
            },
            "ftp": {
                "description": "File Transfer Protocol",
                "risks": [
                    "Unencrypted credentials",
                    "Plain text data",
                    "Outdated protocol",
                ],
                "recommendations": [
                    "Use SFTP instead",
                    "Disable FTP",
                    "Use SSH/SCP",
                    "Never expose to internet",
                ],
            },
            "postgres": {
                "description": "PostgreSQL Database",
                "risks": ["Network exposure", "Brute force", "Default credentials"],
                "recommendations": [
                    "Private network only",
                    "Strong passwords",
                    "Firewall rules",
                    "SSL connections",
                ],
            },
            "redis": {
                "description": "Redis Cache",
                "risks": [
                    "No authentication by default",
                    "Data exposure",
                    "Network attacks",
                ],
                "recommendations": [
                    "Internal network only",
                    "Enable AUTH",
                    "Use firewall",
                    "Strong passwords",
                ],
            },
        }

        for service, info in services.items():
            if service in message.lower():
                response += f"{info['description']}:\n\n"
                response += "Risks:\n"
                for risk in info["risks"]:
                    response += f"  • {risk}\n"
                response += "\nRecommendations:\n"
                for rec in info["recommendations"]:
                    response += f"  ✓ {rec}\n"
                response += "\n"

        return response

    def _generate_security_advice(self, message: str) -> str:
        """Generate general security advice."""
        response = "🔐 Security Recommendations:\n\n"

        response += "Core Security Principles:\n"
        response += "  1. Principle of Least Privilege\n"
        response += "     - Give users/services only necessary permissions\n\n"
        response += "  2. Defense in Depth\n"
        response += (
            "     - Use multiple layers of security (firewall, auth, encryption)\n\n"
        )
        response += "  3. Keep Systems Updated\n"
        response += "     - Patch OS, applications, and libraries regularly\n\n"
        response += "  4. Monitor & Log\n"
        response += "     - Track system activities and review logs\n\n"
        response += "  5. Use Strong Encryption\n"
        response += "     - TLS/SSL for data in transit\n"
        response += "     - AES-256 for data at rest\n\n"
        response += "  6. Implement Authentication\n"
        response += "     - Multi-factor authentication where possible\n"
        response += "     - Key-based auth instead of passwords\n\n"
        response += "  7. Regular Backups\n"
        response += "     - Test restoration procedures\n"
        response += "     - Keep offline copies\n"

        return response

    def _generate_default_response(self, message: str) -> str:
        """Generate default response for unrecognized queries."""
        response = "📋 CyberSec-CLI Analysis\n\n"
        response += "I can help you with security analysis of:\n\n"
        response += "  • Port Security (e.g., 'What about port 22?')\n"
        response += "  • Service Security (e.g., 'Is MySQL secure?')\n"
        response += "  • Network Security (e.g., 'How to secure my server?')\n"
        response += "  • Vulnerability Analysis (e.g., 'What's the risk?')\n\n"
        response += "For more advanced AI analysis, configure your OpenAI API key.\n"
        response += (
            "Set OPENAI_API_KEY environment variable to enable GPT-4 analysis.\n"
        )

        return response

    async def stream_response(
        self,
        messages: List[Dict],
        tools: Optional[List[Dict]] = None,
        temperature: float = None,
        max_tokens: int = None,
    ) -> AsyncGenerator[str, None]:
        """Stream the AI response token by token, or use fallback analysis."""
        if self.use_api:
            async for chunk in self._stream_api_response(
                messages, tools, temperature, max_tokens
            ):
                yield chunk
        else:
            # For fallback, yield the response as if it were streaming
            response = await self.generate_response(
                messages, tools, temperature, max_tokens
            )
            for char in response.content:
                yield char

    async def _stream_api_response(
        self,
        messages: List[Dict],
        tools: Optional[List[Dict]] = None,
        temperature: float = None,
        max_tokens: int = None,
    ) -> AsyncGenerator[str, None]:
        """Stream response from OpenAI API."""
        if not self.api_key:
            raise ValueError("API key is required")

        if not self.session:
            self.session = aiohttp.ClientSession()

        temperature = temperature or settings.ai.temperature
        max_tokens = max_tokens or settings.ai.max_tokens

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }
        safe_headers = {
            k: v
            for k, v in headers.items()
            if "key" not in k.lower()
            and "auth" not in k.lower()
            and "secret" not in k.lower()
        }

        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "stream": True,
        }

        if tools:
            payload["tools"] = tools

        try:
            async with self.session.post(
                f"{self.base_url}/chat/completions", headers=headers, json=payload
            ) as response:
                response.raise_for_status()

                async for line in response.content:
                    if line.startswith(b"data: "):
                        chunk = line[6:].strip()
                        if chunk == b"[DONE]":
                            break

                        try:
                            data = json.loads(chunk)
                            if "choices" in data and data["choices"]:
                                delta = data["choices"][0].get("delta", {})
                                if "content" in delta:
                                    yield delta["content"]
                        except json.JSONDecodeError:
                            continue

        except Exception as e:
            logger.error(f"Error streaming AI response: {str(e)}")
            logger.debug("AI request headers (scrubbed): %s", safe_headers)
            logger.info("Falling back to non-streaming response")
            response = await self.generate_response(
                messages, tools, temperature, max_tokens
            )
            for char in response.content:
                yield char

    def parse_command_intent(self, message: str) -> Dict:
        """Parse natural language into a structured command intent."""
        parser = CommandParser()
        return parser.parse(message).to_dict()
