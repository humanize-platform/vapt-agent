"""
AI Security Tutor for VAPT Agent.

Provides an interactive AI assistant that helps users understand
security vulnerabilities and remediation strategies.
"""

import os
from typing import List, Tuple
from anthropic import Anthropic


class SecurityTutor:
    """AI-powered security education assistant."""
    
    def __init__(self):
        """Initialize the Security Tutor with Anthropic API."""
        # Use same credentials environment variables
        self.use_bedrock = os.getenv("CLAUDE_CODE_USE_BEDROCK", "0") == "1"
        
        if not self.use_bedrock:
            api_key = os.getenv("ANTHROPIC_API_KEY")
            if api_key:
                self.client = Anthropic(api_key=api_key)
                self.available = True
            else:
                self.client = None
                self.available = False
        else:
            # For Bedrock, we'll use the agent SDK approach
            self.client = None
            self.available = False  # Disable for now with Bedrock
    
    def chat(
        self,
        message: str,
        report_context: str,
        history: List[Tuple[str, str]]
    ) -> str:
        """
        Handle a chat message from the user.
        
        Args:
            message: User's question
            report_context: VAPT report content for context
            history: Previous chat messages [(user_msg, assistant_msg), ...]
            
        Returns:
            Assistant's response
        """
        if not self.available or not self.client:
            return ("🔧 AI Tutor is currently only available when using Anthropic API " +
                   "(not AWS Bedrock). Please set ANTHROPIC_API_KEY in your .env file.")
        
        # Build conversation context
        system_prompt = self._build_system_prompt(report_context)
        
        # Convert history to Anthropic format
        messages = []
        for user_msg, assistant_msg in history:
            messages.append({"role": "user", "content": user_msg})
            messages.append({"role": "assistant", "content": assistant_msg})
        
        # Add current message
        messages.append({"role": "user", "content": message})
        
        try:
            response = self.client.messages.create(
                model="claude-3-5-sonnet-20241022",
                max_tokens=1024,
                system=system_prompt,
                messages=messages
            )
            
            return response.content[0].text
            
        except Exception as e:
            return f"❌ Error communicating with AI Tutor: {str(e)}"
    
    def _build_system_prompt(self, report_context: str) -> str:
        """
        Build the system prompt for the AI tutor.
        
        Args:
            report_context: VAPT report content
            
        Returns:
            System prompt string
        """
        context_preview = report_context[:2000] if report_context else "No report available yet."
        
        return f"""You are a friendly and knowledgeable security tutor helping developers understand API vulnerabilities and security best practices.

**Your Role:**
- Explain security concepts in simple, beginner-friendly terms
- Use analogies and real-world examples when helpful
- Provide actionable remediation steps
- Be encouraging and educational
- Focus on practical security advice

**VAPT Report Context:**
```
{context_preview}
```

**Guidelines:**
1. When explaining vulnerabilities, break them down into:
   - What it is (simple definition)
   - Why it's dangerous (impact)
   - How to fix it (remediation)
   - How to prevent it (best practices)

2. Use clear examples and avoid jargon unless explaining it

3. If asked about specific findings from the report, reference them directly

4. Keep responses concise but comprehensive (aim for 150-300 words)

5. Include code examples when relevant for remediation

6. Always be supportive - security is complex, and learning is a journey!
"""


# Global tutor instance
_tutor_instance = None


def get_tutor() -> SecurityTutor:
    """Get or create the global SecurityTutor instance."""
    global _tutor_instance
    if _tutor_instance is None:
        _tutor_instance = SecurityTutor()
    return _tutor_instance
