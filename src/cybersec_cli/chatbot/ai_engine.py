"""
AI Engine for the Cybersec CLI chatbot.
Handles communication with AI models and response generation.
"""
from typing import Dict, List, Optional, AsyncGenerator
import json
import logging
from pathlib import Path

import aiohttp
from pydantic import BaseModel, Field

from cybersec_cli.config import settings

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
    """Handles communication with AI models."""
    
    def __init__(self, api_key: str = None, model: str = None):
        self.api_key = api_key or settings.ai.api_key
        self.model = model or settings.ai.model
        self.base_url = "https://api.openai.com/v1"
        self.session = None
        
    async def __aenter__(self):
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
        max_tokens: int = None
    ) -> AIResponse:
        """Generate a response from the AI model."""
        if not self.api_key:
            raise ValueError("API key is required")
            
        if not self.session:
            self.session = aiohttp.ClientSession()
            
        temperature = temperature or settings.ai.temperature
        max_tokens = max_tokens or settings.ai.max_tokens
        
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}"
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
                f"{self.base_url}/chat/completions",
                headers=headers,
                json=payload
            ) as response:
                response.raise_for_status()
                data = await response.json()
                
                choice = data["choices"][0]["message"]
                return AIResponse(
                    content=choice.get("content", ""),
                    tool_calls=choice.get("tool_calls", []),
                    model=data["model"],
                    usage=data.get("usage")
                )
                
        except Exception as e:
            logger.error(f"Error generating AI response: {str(e)}")
            raise
    
    async def stream_response(
        self,
        messages: List[Dict],
        tools: Optional[List[Dict]] = None,
        temperature: float = None,
        max_tokens: int = None
    ) -> AsyncGenerator[str, None]:
        """Stream the AI response token by token."""
        if not self.api_key:
            raise ValueError("API key is required")
            
        if not self.session:
            self.session = aiohttp.ClientSession()
            
        temperature = temperature or settings.ai.temperature
        max_tokens = max_tokens or settings.ai.max_tokens
        
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}"
        }
        
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "stream": True
        }
        
        if tools:
            payload["tools"] = tools
            
        try:
            async with self.session.post(
                f"{self.base_url}/chat/completions",
                headers=headers,
                json=payload
            ) as response:
                response.raise_for_status()
                
                async for line in response.content:
                    if line.startswith(b'data: '):
                        chunk = line[6:].strip()
                        if chunk == b'[DONE]':
                            break
                            
                        try:
                            data = json.loads(chunk)
                            if 'choices' in data and data['choices']:
                                delta = data['choices'][0].get('delta', {})
                                if 'content' in delta:
                                    yield delta['content']
                        except json.JSONDecodeError:
                            continue
                            
        except Exception as e:
            logger.error(f"Error streaming AI response: {str(e)}")
            raise

    async def parse_command_intent(self, message: str) -> Dict:
        """Parse natural language into command intent."""
        # This will be implemented to extract commands and parameters
        # from natural language input
        pass
