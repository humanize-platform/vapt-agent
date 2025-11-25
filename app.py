"""
Gradio Web Interface for VAPT Agent.

This module provides a user-friendly web interface for the VAPT (Vulnerability 
Assessment and Penetration Testing) agent, allowing users to:
- Input API endpoint, HTTP method, and API key
- View real-time progress of security testing
- Download the generated security report
"""

import asyncio
import gradio as gr
from datetime import datetime
from pathlib import Path
from typing import Optional, Generator
import json
import threading
import time

from vapt_agent import run_vapt_agent_with_callback
from config import VAPTConfig


def run_security_test(
    api_endpoint: str,
    http_method: str,
    api_key: Optional[str] = None,
) -> Generator:
    """
    Run VAPT security test and yield updates for Gradio UI.
    
    Args:
        api_endpoint: The API endpoint to test
        http_method: HTTP method (GET, POST, PUT, DELETE, PATCH)
        api_key: Optional API key for authentication
        
    Yields:
        Tuple of (progress_text, report_markdown, report_file_path)
    """
    
    # Validation
    if not api_endpoint or not api_endpoint.strip():
        yield (
            "❌ Error: API endpoint is required",
            "## Error\n\nPlease provide a valid API endpoint URL.",
            None
        )
        return
    
    if not api_endpoint.startswith(("http://", "https://")):
        yield (
            "❌ Error: Invalid URL format",
            "## Error\n\nAPI endpoint must start with `http://` or `https://`.",
            None
        )
        return
    
    # Initialize progress
    progress_messages = []
    
    def add_progress(message: str):
        """Helper to add and format progress messages."""
        progress_messages.append(f"[{datetime.now().strftime('%H:%M:%S')}] {message}")
        return "\n".join(progress_messages)
    
    # Start testing
    yield (
        add_progress("🚀 Initializing VAPT Agent..."),
        "## Starting Security Test\n\nPlease wait while we assess your API endpoint...",
        None
    )
    
    # Prepare headers
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "VAPT-Agent/1.0"
    }
    
    if api_key and api_key.strip():
        headers["Authorization"] = f"Bearer {api_key.strip()}"
        yield (
            add_progress("🔑 API key provided - will test authenticated endpoints"),
            "## Starting Security Test\n\nPreparing to test with authentication...",
            None
        )
    
    # Progress callback for agent (thread-safe)
    progress_lock = threading.Lock()
    
    def progress_callback(message: str):
        """Callback to receive progress updates from agent."""
        with progress_lock:
            progress_messages.append(f"[{datetime.now().strftime('%H:%M:%S')}] {message}")
    
    # Run the agent in a background thread
    result_container = {"report_content": None, "report_file_path": None, "error": None, "done": False}
    
    def run_agent_thread():
        """Run the agent in a separate thread."""
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            report_content, report_file_path = loop.run_until_complete(
                run_vapt_agent_with_callback(
                    api_endpoint=api_endpoint,
                    method=http_method,
                    headers=headers,
                    progress_callback=progress_callback
                )
            )
            
            loop.close()
            
            result_container["report_content"] = report_content
            result_container["report_file_path"] = report_file_path
            
        except asyncio.TimeoutError:
            result_container["error"] = "Timeout: Security test took too long"
        except Exception as e:
            result_container["error"] = str(e)
        finally:
            result_container["done"] = True
    
    # Start the agent thread
    yield (
        add_progress("🔌 Connecting to Claude Agent SDK..."),
        "## Starting Security Test\n\nConnecting to Claude Agent...",
        None
    )
    
    agent_thread = threading.Thread(target=run_agent_thread, daemon=True)
    agent_thread.start()
    
    # Poll for progress updates while agent is running
    last_message_count = len(progress_messages)
    
    while not result_container["done"]:
        time.sleep(0.5)  # Poll every 500ms
        
        # Check if there are new messages
        with progress_lock:
            current_message_count = len(progress_messages)
            if current_message_count > last_message_count:
                # New messages available, yield update
                yield (
                    "\n".join(progress_messages),
                    "## Security Test in Progress\n\nPlease wait while the agent performs security testing...",
                    None
                )
                last_message_count = current_message_count
    
    # Agent finished, handle results
    if result_container["error"]:
        error_msg = result_container["error"]
        if "Timeout" in error_msg:
            yield (
                add_progress(f"⏱️ {error_msg}"),
                "## Error\n\n**Timeout Error**\n\nThe security assessment exceeded the timeout limit. This might happen with slow APIs or extensive testing.",
                None
            )
        else:
            yield (
                add_progress(f"❌ Error: {error_msg}"),
                f"## Error\n\n**Exception Occurred**\n\n```\n{error_msg}\n```\n\nPlease check your configuration and try again.",
                None
            )
    else:
        # Success
        report_content = result_container["report_content"]
        report_file_path = result_container["report_file_path"]
        
        yield (
            add_progress("✅ Security assessment completed successfully!"),
            report_content if report_content else "## Error\n\nNo report was generated.",
            report_file_path
        )


def create_gradio_interface():
    """Create and configure the Gradio interface."""
    
    with gr.Blocks(title="VAPT Agent - API Security Testing") as interface:
        
        gr.Markdown("# 🛡️ VAPT Agent - API Security Testing")
        
        with gr.Row():
            with gr.Column(scale=1):
                gr.Markdown(
                    """
                    **Two-Step Automated Security Testing:**
                    
                    1️⃣ **API Spec Generation** - Uses Postman MCP Server to auto-discover and document your API  
                    2️⃣ **VAPT Testing** - Runs comprehensive security tests using custom MCP tools
                    """
                )
            with gr.Column(scale=1):
                gr.Markdown(
                    """
                    **Security Tests Performed:**
                    
                    ✓ SQL Injection • XSS • Auth/Authorization  
                    ✓ Rate Limiting • CORS Policy • Security Headers
                    """
                )
        
        with gr.Row():
            with gr.Column(scale=1):
                gr.Markdown("### 📋 API Configuration")
                
                api_endpoint = gr.Textbox(
                    label="API Endpoint URL",
                    placeholder="https://api.example.com/v1/users",
                    value="https://jsonplaceholder.typicode.com/posts",
                    info="The complete URL of the API endpoint to test"
                )
                
                http_method = gr.Dropdown(
                    label="HTTP Method",
                    choices=["GET", "POST", "PUT", "DELETE", "PATCH"],
                    value="GET",
                    info="Select the HTTP method for the endpoint"
                )
                
                api_key = gr.Textbox(
                    label="API Key (Optional)",
                    placeholder="Enter your API key or Bearer token",
                    type="password",
                    info="If your API requires authentication, provide the key here"
                )
                
                with gr.Row():
                    submit_btn = gr.Button("🚀 Start Security Test", variant="primary", size="lg")
                    clear_btn = gr.Button("🔄 Clear", variant="secondary")
                
                gr.HTML(
                    "<div style='width: 100%; padding: 8px; background-color: #fff3cd; border-left: 4px solid #ffc107; margin: 8px 0;'>⚠️ <strong>Disclaimer:</strong> This tool is for authorized security testing only. Always obtain proper authorization before testing.</div>"
                )
            
            with gr.Column(scale=2):
                gr.Markdown("### 📊 Test Results")
                
                with gr.Tab("Live Progress"):
                    progress_output = gr.Textbox(
                        label="Agent Activity",
                        lines=15,
                        max_lines=20,
                        interactive=False,
                        placeholder="Agent activity will appear here..."
                    )
                
                with gr.Tab("Security Report"):
                    report_file = gr.File(
                        label="📥 Download Report (.md)",
                        interactive=False,
                        visible=True
                    )
                    
                    report_output = gr.Markdown(
                        value="Security report will appear here after the test completes...",
                        label="VAPT Report"
                    )
        
        # Event handlers
        submit_btn.click(
            fn=run_security_test,
            inputs=[api_endpoint, http_method, api_key],
            outputs=[progress_output, report_output, report_file],
            show_progress=True
        )
        
        clear_btn.click(
            fn=lambda: (
                "https://jsonplaceholder.typicode.com/posts",
                "GET",
                "",
                "",
                "Security report will appear here after the test completes...",
                None
            ),
            inputs=[],
            outputs=[api_endpoint, http_method, api_key, progress_output, report_output, report_file]
        )
    
    return interface


def main():
    """Launch the Gradio interface."""
    
    print("=" * 80)
    print("VAPT Agent - Gradio Web Interface")
    print("=" * 80)
    
    try:
        # Validate configuration
        config = VAPTConfig()
        print(f"✓ Configuration loaded successfully")
        print(f"  Provider: {'AWS Bedrock' if config.use_bedrock else 'Anthropic API'}")
        print(f"  Model: {config.model_name}")
        if config.use_bedrock:
            print(f"  Region: {config.aws_region}")
        print()
        
    except Exception as e:
        print(f"❌ Configuration error: {e}")
        print("Please check your .env file and ensure all required variables are set.")
        return
    
    # Create and launch interface
    interface = create_gradio_interface()
    
    print("Starting Gradio server...")
    print("=" * 80)
    
    interface.launch(
        server_name="0.0.0.0",
        server_port=7861,
        share=False,
        inbrowser=True
    )


if __name__ == "__main__":
    main()
