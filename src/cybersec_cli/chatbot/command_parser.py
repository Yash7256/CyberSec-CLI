"""
Command parser for the Cybersec CLI.
Handles natural language processing and command extraction.
"""
import re
from typing import Dict, List, Optional, Tuple, Union
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)

@dataclass
class Command:
    """Represents a parsed command with its parameters."""
    action: str
    target: Optional[str] = None
    parameters: Dict[str, Union[str, int, bool, List[str]]] = None
    raw_input: str = ""
    
    def __post_init__(self):
        if self.parameters is None:
            self.parameters = {}
    
    def to_dict(self) -> Dict:
        """Convert command to dictionary."""
        return {
            "action": self.action,
            "target": self.target,
            "parameters": self.parameters,
            "raw_input": self.raw_input
        }
    
    def __str__(self) -> str:
        params = ", ".join(f"{k}={v}" for k, v in self.parameters.items())
        return f"Command(action='{self.action}', target='{self.target}', {params})"

class CommandParser:
    """Parses natural language into structured commands."""
    
    # Define command patterns with regex
    COMMAND_PATTERNS = {
        # Network scanning
        "scan_ports": [
            r"(?:scan|check)\s+(?:port|ports)\s+(?P<ports>[\d,\-\s]+)?\s*(?:on|for|at)?\s*(?P<target>[\w\.\-:]+)",
            r"scan\s+(?P<target>[\w\.\-:]+)(?:\s+for\s+ports?\s+(?P<ports>[\d,\-\s]+))?"
        ],
        "scan_network": [
            r"(?:scan|map)\s+(?:network|lan|local network|subnet)",
            r"find\s+(?:devices|hosts|machines)\s+on\s+network"
        ],
        
        # Web security
        "ssl_check": [
            r"(?:check|verify|analyze)\s+ssl\s*(?:of|for|on)?\s*(?P<target>[\w\.\-:]+)",
            r"(?:is\s+)?ssl\s+(?:secure|valid|good)\s+(?:for|on)?\s*(?P<target>[\w\.\-:]+)"
        ],
        "analyze_headers": [
            r"(?:check|analyze|inspect)\s+(?:http\s+)?headers?\s*(?:for|of|on)?\s*(?P<url>https?://[\w\.\-:/]+)",
            r"what(?:'s| is) the\s+(?:security\s+)?header\s+(?:status|info)\s+for\s+(?P<url>https?://[\w\.\-:/]+)"
        ],
        
        # Password security
        "check_password": [
            r"(?:check|analyze|test|is)\s+(?:password\s+)?(?:'|")(?P<password>.+?)(?:'|")(?:\s+secure)?",
            r"how\s+strong\s+is\s+(?:password\s+)?(?:'|")(?P<password>.+?)(?:'|")"
        ],
        
        # Hash operations
        "hash_identify": [
            r"(?:identify|what is|detect|analyze)\s+(?:hash\s+)?(?:'|")(?P<hash>[a-fA-F0-9]+)(?:'|")",
            r"(?:what('s| is) the )?(?:hash\s+)?(?:type|algorithm)\s+of\s+(?:'|")(?P<hash>[a-fA-F0-9]+)(?:'|")"
        ],
        "hash_generate": [
            r"(?:generate|create|make)\s+(?P<algorithm>\w+)\s+hash(?:\s+for|\s+of)?\s*(?:'|")(?P<text>.+?)(?:'|")",
            r"hash\s+(?P<text>.+?)\s+with\s+(?P<algorithm>\w+)"
        ],
        
        # General help
        "help": [
            r"help(?:\s+with\s+(?P<topic>.+))?",
            r"how\s+to\s+(?P<topic>.+)",
            r"what\s+(?:can you do|are my options|commands are available)"
        ],
        
        # System commands
        "clear": [
            r"clear(?:\s+screen)?",
            r"cls"
        ],
        "exit": [
            r"(?:exit|quit|bye|goodbye)"
        ]
    }
    
    # Aliases for commands
    COMMAND_ALIASES = {
        "quit": "exit",
        "bye": "exit",
        "cls": "clear",
        "analyze": "scan_ports",
        "test": "scan_ports",
        "check": "scan_ports"
    }
    
    def __init__(self):
        # Compile all regex patterns for better performance
        self.compiled_patterns = {}
        for cmd, patterns in self.COMMAND_PATTERNS.items():
            self.compiled_patterns[cmd] = [
                re.compile(pattern, re.IGNORECASE) 
                for pattern in patterns
            ]
    
    def parse(self, text: str) -> Command:
        """
        Parse natural language input into a structured command.
        
        Args:
            text: The natural language input to parse
            
        Returns:
            Command: A structured command object
        """
        if not text or not text.strip():
            return Command(action="unknown", raw_input=text)
            
        text = text.strip()
        
        # Check for direct command aliases first
        normalized_text = text.lower().split()[0]
        if normalized_text in self.COMMAND_ALIASES:
            return Command(
                action=self.COMMAND_ALIASES[normalized_text],
                raw_input=text
            )
        
        # Try to match patterns
        for command_name, patterns in self.compiled_patterns.items():
            for pattern in patterns:
                match = pattern.search(text)
                if match:
                    params = match.groupdict()
                    target = params.pop('target', None)
                    
                    # Clean up parameters
                    cleaned_params = {}
                    for key, value in params.items():
                        if value is not None:
                            # Convert string numbers to integers
                            if value.isdigit():
                                value = int(value)
                            # Handle port lists (e.g., "80,443,8080")
                            elif key == 'ports' and isinstance(value, str):
                                ports = []
                                for part in value.split(','):
                                    part = part.strip()
                                    if '-' in part:
                                        start, end = map(int, part.split('-'))
                                        ports.extend(range(start, end + 1))
                                    elif part.isdigit():
                                        ports.append(int(part))
                                value = ports
                            cleaned_params[key] = value
                    
                    return Command(
                        action=command_name,
                        target=target,
                        parameters=cleaned_params,
                        raw_input=text
                    )
        
        # If no specific command matched, treat as a general query
        return Command(
            action="query",
            parameters={"query": text},
            raw_input=text
        )
    
    def get_command_help(self, command_name: str = None) -> str:
        """
        Get help text for a specific command or all commands.
        
        Args:
            command_name: The name of the command to get help for
            
        Returns:
            str: Help text
        """
        if command_name:
            # Return help for specific command
            if command_name in self.COMMAND_PATTERNS:
                return f"Help for '{command_name}': Not implemented yet"
            else:
                return f"Unknown command: {command_name}"
        
        # Return general help
        help_text = ["Available commands:", ""]
        for cmd in sorted(self.COMMAND_PATTERNS.keys()):
            help_text.append(f"  {cmd}: {self._get_command_description(cmd)}")
        
        help_text.extend([
            "",
            "Examples:",
            "  scan ports 80,443 on example.com",
            "  check ssl for google.com",
            "  analyze password 'myp@ssw0rd'",
            "  identify hash 5f4dcc3b5aa765d61d8327deb882cf99",
            "  help"
        ])
        
        return "\n".join(help_text)
    
    def _get_command_description(self, command_name: str) -> str:
        """Get a brief description of a command."""
        descriptions = {
            "scan_ports": "Scan ports on a target host",
            "scan_network": "Scan the local network for devices",
            "ssl_check": "Check SSL/TLS configuration of a website",
            "analyze_headers": "Analyze HTTP headers for security issues",
            "check_password": "Check password strength and security",
            "hash_identify": "Identify the type of a hash",
            "hash_generate": "Generate a hash from text",
            "help": "Show this help message",
            "clear": "Clear the terminal screen",
            "exit": "Exit the program"
        }
        return descriptions.get(command_name, "No description available")
