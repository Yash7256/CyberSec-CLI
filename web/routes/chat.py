from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Optional
import logging
from src.cybersec_cli.chatbot.ai_engine import AIEngine

# Configure logger
logger = logging.getLogger("api.chat")

router = APIRouter(prefix="/api", tags=["AI Chat"])

# Initialize AI engine globally (simple approach)
# Ideally this would be dependency injected or initialized on startup
try:
    ai_engine = AIEngine()
except Exception as e:
    logger.critical(f"ChatService init failed: {e}", exc_info=True)
    raise RuntimeError("Cannot start: ChatService unavailable") from e

class ChatMessage(BaseModel):
    role: str
    content: str

class ChatRequest(BaseModel):
    messages: List[ChatMessage]
    context: Optional[str] = None # Optional context (e.g., current scan result)

class ChatResponse(BaseModel):
    role: str
    content: str

@router.post("/chat", response_model=ChatResponse)
async def chat_endpoint(request: ChatRequest):
    """
    Send a message to the Groq AI chatbot.
    """
    try:
        # Convert Pydantic models to dicts
        messages = [m.dict() for m in request.messages]
        
        # Inject System Prompt if not present
        if not messages or messages[0].get("role") != "system":
            system_prompt = (
                "You are CyberSec-AI, an expert cybersecurity assistant integrated into the CyberSec-CLI tool. "
                "Your goal is to help users analyze network scan results, explain vulnerabilities, and suggest remediation steps. "
                "Be concise, professional, and focus on actionable security advice.\n\n"
                "FORMATTING GUIDELINES:\n"
                "- Use Markdown for all your responses.\n"
                "- Use clear headers (##, ###) to organize information.\n"
                "- Use tables for data comparisons or port lists.\n"
                "- Use bullet points for remediation steps and vulnerability impacts.\n"
                "- Use code blocks for commands, payloads, or raw data.\n"
                "- Bold important technical terms.\n\n"
                "If the user provides raw scan data (JSON/Text), analyze it for risks.\n\n"
                "IMPORTANT RESTRICTION: You MUST ONLY answer questions related to:\n"
                "- Cybersecurity (vulnerabilities, exploits, security best practices, penetration testing, etc.)\n"
                "- Networking (ports, protocols, firewalls, DNS, TCP/IP, routing, etc.)\n"
                "- Engineering (software engineering, system administration, DevOps, infrastructure, etc.)\n\n"
                "If the user asks about ANY other topic, politely decline and redirect them."
            )
            messages.insert(0, {"role": "system", "content": system_prompt})
            
        # If specific context is provided, append it to the system prompt or as a context message
        if request.context:
            context_msg = {
                "role": "system", 
                "content": f"Current Context / Scan Result:\n{request.context}"
            }
            # Insert after the main system prompt
            messages.insert(1, context_msg)
            
        # Call AI engine (OpenAI if configured; otherwise fallback)
        response = await ai_engine.generate_response(messages)
        return ChatResponse(role="assistant", content=response.content)
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Chat API Error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Internal AI Error: {str(e)}")
