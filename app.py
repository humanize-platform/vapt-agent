# Gradio Web Interface for VAPT Agent

"""
Modern Gradio UI for the VAPT (Vulnerability Assessment and Penetration Testing) agent.

Features:
- Input API endpoint, HTTP method, and optional API key
- Real-time progress streaming
- Downloadable Markdown report
- Visual Dashboard (risk gauge & severity pie chart)
- AI Security Tutor (interactive Q&A about the report)
"""

import asyncio
import gradio as gr
from datetime import datetime
import threading
import time
from typing import Optional, Generator, List, Tuple

from vapt_agent import run_vapt_agent_with_callback
from config import VAPTConfig
from dashboard_utils import (
    parse_vapt_report,
    calculate_risk_score,
    create_severity_chart,
    create_risk_gauge,
)
from ai_tutor import get_tutor

import os

CSS_PATH = os.path.join(os.path.dirname(__file__), "vapt_styles.css")


def load_custom_css(path: str = CSS_PATH) -> str:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        # Fail silently; app will still run without custom CSS
        return ""


# ---------------------------------------------------------------------------
# Helper: run the VAPT agent and stream updates to Gradio
# ---------------------------------------------------------------------------


def run_security_test(
    api_endpoint: str,
    http_method: str,
    api_key: Optional[str] = None,
) -> Generator[Tuple[str, str, str], None, None]:
    """Yield progress, report markdown and report file path for Gradio.

    The function validates inputs, starts the VAPT agent in a background thread,
    and periodically yields any new progress messages.
    """
    # ---------- Validation ----------
    if not api_endpoint or not api_endpoint.strip():
        yield (
            "❌ Error: API endpoint is required",
            "## Error\n\nPlease provide a valid API endpoint URL.",
            None,
        )
        return
    if not api_endpoint.startswith(("http://", "https://")):
        yield (
            "❌ Error: Invalid URL format",
            "## Error\n\nAPI endpoint must start with `http://` or `https://`.",
            None,
        )
        return

    # ---------- Progress handling ----------
    progress_messages: List[str] = []
    lock = threading.Lock()

    def add_progress(msg: str) -> str:
        with lock:
            progress_messages.append(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")
            return "\n".join(progress_messages)

    def progress_callback(msg: str):
        with lock:
            progress_messages.append(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")

    # Initial message
    yield (
        add_progress("🚀 Initializing VAPT Agent..."),
        "## Starting Security Test\n\nPlease wait while we assess your API endpoint...",
        None,
    )

    # Prepare request headers
    headers = {"Content-Type": "application/json", "User-Agent": "VAPT-Agent/1.0"}
    if api_key and api_key.strip():
        headers["Authorization"] = f"Bearer {api_key.strip()}"
        yield (
            add_progress("🔑 API key provided – will test authenticated endpoints"),
            "## Starting Security Test\n\nPreparing to test with authentication...",
            None,
        )

    # ---------- Run agent in background thread ----------
    result = {
        "report_content": None,
        "report_file_path": None,
        "error": None,
        "done": False,
    }

    def agent_worker():
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            content, path = loop.run_until_complete(
                run_vapt_agent_with_callback(
                    api_endpoint=api_endpoint,
                    method=http_method,
                    headers=headers,
                    progress_callback=progress_callback,
                )
            )
            loop.close()
            result["report_content"] = content
            result["report_file_path"] = path
        except asyncio.TimeoutError:
            result["error"] = "Timeout: Security test took too long"
        except Exception as e:
            result["error"] = str(e)
        finally:
            result["done"] = True

    # Connect to LLM backend – just a placeholder progress update
    yield (
        add_progress("🔌 Connecting to security engine..."),
        "## Starting Security Test\n\nConnecting...",
        None,
    )
    threading.Thread(target=agent_worker, daemon=True).start()

    # ---------- Poll for updates ----------
    last_len = 0
    while not result["done"]:
        time.sleep(0.5)
        with lock:
            if len(progress_messages) > last_len:
                yield (
                    "\n".join(progress_messages),
                    "## Security Test in Progress\n\nPlease wait while the agent performs testing...",
                    None,
                )
                last_len = len(progress_messages)

    # ---------- Final handling ----------
    if result["error"]:
        err = result["error"]
        if "Timeout" in err:
            yield (
                add_progress(f"⏱️ {err}"),
                "## Error\n\n**Timeout Error**\n\nThe assessment exceeded the allowed time.",
                None,
            )
        else:
            yield (
                add_progress(f"❌ Error: {err}"),
                f"## Error\n\n**Exception Occurred**\n\n```\n{err}\n```\n\nPlease check configuration and retry.",
                None,
            )
    else:
        # Success – return report and file path
        yield (
            add_progress("✅ Security assessment completed successfully!"),
            result["report_content"] or "## Error\n\nNo report was generated.",
            result["report_file_path"],
        )


# ---------------------------------------------------------------------------
# Gradio UI construction
# ---------------------------------------------------------------------------


def create_gradio_interface() -> gr.Blocks:
    with gr.Blocks(title="VAPT Agent") as iface:

        # Inject custom CSS – light theme, white cards, improved readability
        custom_css = load_custom_css()
        if custom_css:
            gr.HTML(f"<style>{custom_css}</style>")

        # --- Header ---
        with gr.Row(elem_id="app-header"):
            with gr.Column(scale=6):
                gr.Markdown(
                    """
                    <div>
                      <div class="badge-pill">
                        <span class="dot"></span>
                        <span>Agentic VAPT • API Security</span>
                      </div>
                      <h1>VAPT Agent Dashboard</h1>
                      <p>
                     Generate API specs, run automated vulnerability tests, and explore results with an AI security tutor. Gain clear insights into API risks, misconfigurations, and recommended remediation steps in dashboard.
                      </p>
                    </div>
                    """,
                    elem_id="header-title",
                )
            with gr.Column(scale=4):
                gr.Markdown(
                    """
                    **Workflow Overview**
                    
                    1. Provide an API endpoint and method  
                    2. Agent discovers endpoints and builds the API spec using Postman MCP 
                    3. Customized VAPT MCP tools run automated security tests  
                    4. Dashboard + Tutor help you interpret and fix issues  
                    """,
                )

        # --- Main two-column layout ---
        with gr.Row():
            # Left: API configuration
            with gr.Column(scale=5):
                with gr.Group(elem_id="config-card", elem_classes=["section-card"]):
                    gr.Markdown("### 📋 API Configuration")

                    api_endpoint = gr.Textbox(
                        label="API Endpoint URL",
                        placeholder="https://sandbox.api.sap.com/SAPCALM/calm-tasks/v1/tasks?projectId=111",
                        value="https://sandbox.api.sap.com/SAPCALM/calm-tasks/v1/tasks?projectId=111",
                        info="Full URL of the API endpoint to test",
                    )
                    http_method = gr.Dropdown(
                        label="HTTP Method",
                        choices=["GET", "POST", "PUT", "DELETE", "PATCH"],
                        value="GET",
                        info="Select the HTTP method for the endpoint",
                    )
                    api_key = gr.Textbox(
                        label="API Key (Optional)",
                        placeholder="Enter your API key or Bearer token",
                        type="password",
                        value="Ww9aGPGeGoDGCFetcBtsaEtGOpGSUNXp",
                        info="If the API requires authentication, provide the key here",
                    )
                    with gr.Row():
                        submit_btn = gr.Button(
                            "🚀 Start Security Test", variant="primary", size="lg"
                        )
                        clear_btn = gr.Button(
                            "🔄 Reset", variant="secondary", elem_id="reset-btn"
                        )

                    gr.HTML(
                        """
                        <div id="disclaimer-box">
                          ⚠️ <strong>Authorized use only:</strong> Run this tool only against systems and APIs you are explicitly allowed to test.
                        </div>
                        """
                    )

            # Right: Results area
            with gr.Column(scale=7):
                with gr.Group(elem_id="results-card", elem_classes=["section-card"]):
                    gr.Markdown("### 📊 Security Assessment Results")

                    with gr.Tab("Live Progress"):
                        progress_output = gr.Textbox(
                            label="Agent Activity Log",
                            lines=15,
                            max_lines=20,
                            interactive=False,
                            show_label=False,
                            placeholder="Agent activity will appear here...",
                        )

                    with gr.Tab("Security Report"):
                        report_file = gr.File(
                            label="📥 Download Report (.md)",
                            interactive=False,
                            visible=True,
                        )
                        report_output = gr.Markdown(
                            value="Security report will appear here after the test completes...",
                            label="VAPT Report",
                            elem_id="security-report-md",
                        )

                    with gr.Tab("Dashboard"):
                        # Row that we'll center via CSS
                        with gr.Row(elem_id="dashboard-row"):
                            with gr.Column(scale=1, elem_id="risk-col"):
                                risk_gauge = gr.Plot(label="Risk Score")
                            with gr.Column(scale=1, elem_id="severity-col"):
                                severity_pie = gr.Plot(
                                    label="Vulnerability Distribution"
                                )

                        top_findings = gr.Markdown(
                            "Run a security test to see summarized key findings..."
                        )

                    with gr.Tab("Security Tutor"):
                        with gr.Column(elem_id="tutor-section"):
                            gr.Markdown(
                            """
                            <div style="font-size: 0.95rem; line-height: 1.5; margin-bottom: 0.4rem;">
                            <strong>Ask questions about your security report.</strong><br/>
                            Get clear explanations, remediation guidance, and best-practice advice.
                            </div>
                            """
                            )   
                            chatbot = gr.Chatbot(
                                label="Security Tutor",
                                height=380,
                                elem_id="tutor-chat",
                            )

                            with gr.Row(elem_id="tutor-input-row"):
                                tutor_input = gr.Textbox(
                                    label="Your Question",
                                    placeholder="e.g., What is SQL injection and how do I fix it?",
                                    lines=2,
                                    scale=4,
                                    show_label=True,
                                )
                                tutor_btn = gr.Button("Ask", variant="primary", scale=1)

                            gr.HTML(
                                """
                                <div id="tutor-examples">
                                  <strong>Example questions you can ask:</strong>
                                  <ul>
                                    <li>What is the most critical issue in my report?</li>
                                    <li>How do I fix CORS policy issues?</li>
                                    <li>Explain SQL injection in simple terms.</li>
                                    <li>What should I fix first to reduce risk quickly?</li>
                                  </ul>
                                </div>
                                """
                            )

        # -------------------------------------------------------------------
        # Event bindings
        # -------------------------------------------------------------------

        # VAPT run
        submit_btn.click(
            fn=run_security_test,
            inputs=[api_endpoint, http_method, api_key],
            outputs=[progress_output, report_output, report_file],
            show_progress=True,
        )

        # Reset
        clear_btn.click(
            fn=lambda: (
                "https://sandbox.api.sap.com/SAPCALM/calm-tasks/v1/tasks?projectId=111",
                "GET",
                "",
                "",
                "Security report will appear here after the test completes...",
                None,
            ),
            inputs=[],
            outputs=[
                api_endpoint,
                http_method,
                api_key,
                progress_output,
                report_output,
                report_file,
            ],
        )

        # Dashboard updates – triggered after a successful report
        def update_dashboard(report_md: str):
            data = parse_vapt_report(report_md)
            sev = data["severities"]
            risk = calculate_risk_score(sev)
            return (
                create_risk_gauge(risk),
                create_severity_chart(sev),
                (
                    "\n".join(data.get("findings", [])[:5])
                    if data.get("findings")
                    else "No findings detected."
                ),
            )

        report_output.change(
            fn=update_dashboard,
            inputs=[report_output],
            outputs=[risk_gauge, severity_pie, top_findings],
        )

        # AI Tutor interaction
        # Gradio Chatbot (v6) uses "messages" format: list of {"role": ..., "content": ...}
        # We convert that to (user, assistant) pairs for the tutor, then convert back.
        def tutor_respond(question, history, report_md: str):
            # 1) Convert Gradio "messages" history -> list of (user, assistant) pairs
            pairs: List[Tuple[str, str]] = []
            current_user = None

            for msg in history or []:
                if isinstance(msg, dict):
                    role = msg.get("role")
                    content = msg.get("content", "")
                elif isinstance(msg, (list, tuple)) and len(msg) == 2:
                    # Backward compatibility: skip old tuple-style entries
                    continue
                else:
                    continue

                if role == "user":
                    current_user = content
                elif role == "assistant":
                    if current_user is None:
                        current_user = ""
                    pairs.append((current_user, content))
                    current_user = None

            # 2) Call the tutor with pairs
            tutor = get_tutor()
            answer = tutor.chat(question, report_md, pairs)

            # 3) Append new user + assistant messages in Gradio's messages format
            new_history = list(history or [])
            new_history.append({"role": "user", "content": question})
            new_history.append({"role": "assistant", "content": answer})

            # Clear the input textbox
            return new_history, ""

        tutor_btn.click(
            fn=tutor_respond,
            inputs=[tutor_input, chatbot, report_output],
            outputs=[chatbot, tutor_input],
        )

    return iface


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def main():
    print("=" * 80)
    print("VAPT Agent - Gradio Web Interface")
    print("=" * 80)
    try:
        cfg = VAPTConfig()
        print(f"✓ Configuration loaded successfully")
        print(f"  Provider: {'AWS Bedrock' if cfg.use_bedrock else 'Anthropic API'}")
        if cfg.use_bedrock:
            print(f"  Region: {cfg.aws_region}")
        print()
    except Exception as exc:
        print(f"❌ Configuration error: {exc}")
        print("Please check your .env file and ensure all required variables are set.")
        return

    iface = create_gradio_interface()
    print("Starting Gradio server...")
    print("=" * 80)
    iface.launch(server_name="0.0.0.0", server_port=7861, share=True, inbrowser=True)


if __name__ == "__main__":
    main()
