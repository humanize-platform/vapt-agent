"""
VAPT Agent - Main module for API security testing.

This module orchestrates the vulnerability assessment and penetration testing
of APIs using Claude Agent SDK with Postman MCP server and custom VAPT tools.
"""

import asyncio
import os
import json
from dotenv import load_dotenv
from pathlib import Path
from typing import Dict, Optional
from datetime import datetime

load_dotenv(override=True)

from claude_agent_sdk import ClaudeSDKClient, ClaudeAgentOptions
from vapt_tools import create_vapt_mcp_server
from config import VAPTConfig
from prompt import SYSTEM_PROMPT, get_vapt_query


async def run_vapt_agent(
    api_endpoint: str,
    method: str = "GET",
    headers: Dict[str, str] = None,
    working_directory: str = None,
) -> None:
    """
    Execute VAPT agent with Postman MCP server and custom security testing tools.
    
    Args:
        api_endpoint: The API endpoint to test
        method: HTTP method for the endpoint
        headers: Optional headers for API requests
        working_directory: Working directory for the agent
    """
    
    config = VAPTConfig()
    
    # Set up AWS Bedrock configuration if enabled
    if config.use_bedrock:
        print("[VAPT Agent] Using AWS Bedrock for Claude")
        os.environ["CLAUDE_CODE_USE_BEDROCK"] = "1"
    
    # Set up Postman MCP server configuration (SSE-based)
    postman_api_key = config.postman_api_key
    if not postman_api_key:
        raise ValueError("POSTMAN_API_KEY not found in environment variables")
    
    postman_mcp_config = {
        "type": "sse",
        "url": "https://mcp.postman.com/mcp",
        "headers": {
            "Authorization": f"Bearer {postman_api_key}"
        }
    }
    
    # Create custom VAPT MCP server
    vapt_tool_server = create_vapt_mcp_server()
    
    # Configure Claude Agent options
    model_name = config.model_name
    
    options = ClaudeAgentOptions(
        system_prompt=SYSTEM_PROMPT,
        mcp_servers={
            "postman": postman_mcp_config,
            "VAPTToolServer": vapt_tool_server,
        },
        allowed_tools=[
            "Read",
            "Write",
            "Bash",
            "Edit",
            "Glob",
            "Grep",
            "WebFetch",
            "WebSearch",
            "mcp__postman__*",  # All Postman MCP tools
            "mcp__VAPTToolServer__vapt_security_test",
        ],
        max_turns=100,
        model=model_name,
        permission_mode="bypassPermissions",
        cwd=Path(working_directory) if working_directory else Path.cwd(),
    )
    
    async with ClaudeSDKClient(options=options) as client:
        print(f"[VAPT Agent] Connected to Claude SDK")
        if config.use_bedrock:
            print(f"[VAPT Agent] Using AWS Bedrock with model: {model_name}")
            print(f"[VAPT Agent] AWS Region: {config.aws_region}")
        else:
            print(f"[VAPT Agent] Using Anthropic API with model: {model_name}")
        print(f"[VAPT Agent] Testing endpoint: {api_endpoint}")
        
        # Construct the query for the agent
        headers_str = json.dumps(headers, indent=2) if headers else "None"
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        query = get_vapt_query(api_endpoint, method, headers_str, timestamp)

        # Execute the query
        timeout_sec = 600  # 10 minutes for security testing
        
        try:
            await asyncio.wait_for(client.query(query), timeout=timeout_sec)
        except asyncio.TimeoutError:
            print(f"[VAPT Agent] Query timed out after {timeout_sec}s")
            raise
        except Exception as e:
            print(f"[VAPT Agent] Query failed: {str(e)}")
            raise
        
        # Stream and print responses
        print("\n[VAPT Agent] Security Testing Results:\n")
        print("=" * 80)
        
        async for message in client.receive_response():
            if hasattr(message, "content"):
                for block in message.content:
                    if hasattr(block, "text") and block.text:
                        print(block.text)
        
        print("\n" + "=" * 80)
        print("[VAPT Agent] Security assessment completed")


def main():
    """Main entry point for VAPT agent."""
    
    config = VAPTConfig()
    
    # Get test configuration
    api_endpoint = config.test_api_endpoint
    method = config.test_api_method
    
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "VAPT-Agent/1.0"
    }
    
    # Add authentication header if provided
    if config.test_api_key:
        headers["Authorization"] = f"Bearer {config.test_api_key}"
    
    print("=" * 80)
    print("VAPT Agent - API Security Testing")
    print("=" * 80)
    if config.use_bedrock:
        print(f"Provider: AWS Bedrock")
        print(f"Region: {config.aws_region}")
        print(f"Model: {config.model_name}")
    else:
        print(f"Provider: Anthropic API")
        print(f"Model: {config.model_name}")
    print(f"Endpoint: {api_endpoint}")
    print(f"Method: {method}")
    print("=" * 80)
    print()
    
    try:
        asyncio.run(run_vapt_agent(
            api_endpoint=api_endpoint,
            method=method,
            headers=headers,
        ))
    except KeyboardInterrupt:
        print("\n[VAPT Agent] Interrupted by user")
    except Exception as e:
        print(f"\n[VAPT Agent] Error: {e}")
        raise


if __name__ == "__main__":
    main()