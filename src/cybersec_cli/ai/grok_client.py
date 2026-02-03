import os
import json
import logging
import asyncio
import urllib.request
import urllib.error
from typing import List, Dict, Optional, Any

logger = logging.getLogger(__name__)

class GrokClient:
    """
    Client for interacting with the Grok AI API (xAI).
    """
    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize the Grok client.
        
        Args:
            api_key: Grok API key. If not provided, looks for GROK_API_KEY env var.
        """
        self.api_key = api_key or os.getenv("GROK_API_KEY")
        self.api_url = "https://api.x.ai/v1/chat/completions"
        self.model = "grok-4-latest"  # Updated model
        
    async def chat_completion(self, messages: List[Dict[str, str]], temperature: float = 0.7) -> Dict[str, Any]:
        """
        Send a chat completion request to Grok API asynchronously.
        
        Args:
            messages: List of message dicts [{"role": "user", "content": "..."}]
            temperature: Sampling temperature
            
        Returns:
            Dict containing the API response
            
        Raises:
            ValueError: If API key is missing
            Exception: If API request fails
        """
        if not self.api_key:
            raise ValueError("GROK_API_KEY is not set. Please configure it in your environment.")
            
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
            "User-Agent": "CyberSec-CLI/1.0",
            "Accept": "application/json"
        }
        
        payload = {
            "messages": messages,
            "model": self.model,
            "temperature": temperature,
            "stream": False
        }
        
        def _perform_request():
            try:
                data = json.dumps(payload).encode('utf-8')
                req = urllib.request.Request(
                    self.api_url,
                    data=data,
                    headers=headers,
                    method="POST"
                )
                with urllib.request.urlopen(req) as response:
                    return json.loads(response.read().decode('utf-8'))
            except urllib.error.HTTPError as e:
                error_body = e.read().decode('utf-8')
                logger.error(f"Grok API HTTP Error {e.code}: {error_body}")
                raise Exception(f"Grok API Error {e.code}: {e.reason}") from e
            except Exception as e:
                logger.error(f"Grok API Request Failed: {str(e)}")
                raise
                
        # Run blocking I/O in a separate thread to avoid blocking the async loop
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, _perform_request)

    async def stream_chat_completion(self, messages: List[Dict[str, str]]) -> Any:
        # Placeholder for streaming support if needed later
        pass
