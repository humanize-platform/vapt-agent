# VAPT Agent - API Security Testing with Claude

A comprehensive vulnerability assessment and penetration testing (VAPT) agent that uses **Claude Agent SDK** with **Postman MCP server** for automated API security testing.

Now featuring a modern **Gradio Web Interface** with a visual dashboard and an **AI Security Tutor** to help you understand and fix vulnerabilities.

## Features

- **Automated Security Testing**: Performs comprehensive security assessments including:
  - SQL Injection detection
  - XSS (Cross-Site Scripting) detection
  - Authentication/Authorization testing
  - Rate limiting verification
  - CORS policy validation
  - Security headers assessment
- **Interactive Web UI**: Modern Gradio interface with real-time progress streaming.
- **Visual Dashboard**: Risk gauge and severity charts to visualize security posture.
- **AI Security Tutor**: Interactive Q&A assistant powered by **Nebius** and **Chroma** vector search to explain findings and remediation steps.
- **Postman Integration**: Uses Postman MCP server (SSE) for automatic API specification creation and testing.

## Architecture & Models

This agent leverages state-of-the-art AI models for different components:

- **VAPT Agent Logic**: Powered by **Haiku 4.5** (via Anthropic API or AWS Bedrock) for fast and efficient security reasoning.
- **AI Security Tutor**: Powered by **gpt-oss-20b** (via Nebius) for high-quality educational explanations.
- **Semantic Search**: Uses **Qwen3-Embedding-8B** (via Nebius) for vectorizing the VAPT report to enable accurate context retrieval for the tutor.

## Prerequisites

- Python 3.10+
- [Postman API Key](https://postman.com/settings/api-keys)
- [Anthropic API Key](https://console.anthropic.com/) OR AWS Bedrock access
- [Nebius API Key](https://nebius.com/) (for AI Tutor)

## Installation

1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd vapt-agent
   ```

2. **Create virtual environment**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment**:
   ```bash
   cp .env.template .env
   # Edit .env with your credentials
   ```

## Configuration

Create a `.env` file with the following variables:

```properties
# --- Core VAPT Agent Configuration ---

# AWS Bedrock (set to 1 to use Bedrock, 0 for Anthropic API)
CLAUDE_CODE_USE_BEDROCK=1

# AWS Credentials (if using Bedrock)
AWS_ACCESS_KEY_ID=your_access_key
AWS_SECRET_ACCESS_KEY=your_secret_key
AWS_REGION=us-east-1

# Model selection for VAPT Agent (Haiku 4.5 recommended)
ANTHROPIC_MODEL=claude-3-haiku-20240307
# If using Anthropic API directly:
# ANTHROPIC_API_KEY=sk-ant-...

# Postman API key (get from https://postman.com/settings/api-keys)
POSTMAN_API_KEY=your_postman_api_key

# --- AI Tutor Configuration (Nebius) ---

# Nebius API Key for Tutor and Embeddings
NEBIUS_API_KEY=your_nebius_api_key

# Nebius Base URL (optional, defaults to standard endpoint)
# NEBIUS_BASE_URL=https://api.tokenfactory.nebius.com/v1

# AI Tutor Chat Model
NEBIUS_TUTOR_MODEL=gpt-oss-20b

# Embedding Model for Vector Search
NEBIUS_EMBEDDING_MODEL=Qwen3-Embedding-8B

# --- Optional Web Search ---
# TAVILY_API_KEY=tvly-...
```

## Usage

### 1. Web Interface (Recommended)

Launch the Gradio dashboard for an interactive experience:

```bash
python app.py
```

- Open your browser at `http://localhost:7861`
- Enter the API endpoint and method.
- Watch the real-time progress log.
- View the generated report, risk dashboard, and chat with the AI Security Tutor.

### 2. Command Line Interface

Run the agent directly from the terminal:

```bash
python vapt_agent.py
```

(Ensure `TEST_API_ENDPOINT` and `TEST_API_METHOD` are set in your `.env` file for CLI usage).

## Security Tests Performed

The agent uses custom MCP tools (`vapt_tools.py`) to perform:

### 1. **Injection Testing**
- SQL Injection with various payloads (e.g., `' OR '1'='1`)
- XSS (Cross-Site Scripting) detection
- Path traversal attempts

### 2. **Authentication Testing**
- Endpoint access without credentials
- Authentication bypass attempts
- Token validation

### 3. **Rate Limiting**
- Burst request testing (50 requests)
- 429 status code detection
- DoS vulnerability assessment

### 4. **CORS Policy**
- Origin validation
- Wildcard (`*`) detection
- Cross-origin request testing

### 5. **Security Headers**
- Strict-Transport-Security (HSTS)
- X-Content-Type-Options
- X-Frame-Options
- Content-Security-Policy
- X-XSS-Protection

## Output

The agent generates a comprehensive Markdown report saved as `vapt_report_YYYYMMDD_HHMMSS.md` containing:
- Executive Summary
- Vulnerability Details (Severity, Description, Evidence, Remediation)
- Risk Score

## Troubleshooting

### Postman API Key Issues
- Get your API key from: https://postman.com/settings/api-keys
- Ensure the key has necessary permissions.

### AWS Bedrock Issues
- Verify AWS credentials are correct.
- Ensure you have access to Claude models in your region.

### AI Tutor Not Working
- Check `NEBIUS_API_KEY` is set.
- Ensure `NEBIUS_EMBEDDING_MODEL` is set to `Qwen3-Embedding-8B` for vector search to work.

## Contributing

Contributions are welcome! Please follow the existing code structure:
- Keep tools modular in `vapt_tools.py`
- Add configuration in `config.py`
- Update `.env.template` for new variables

## License

MIT License

## Disclaimer

This tool is for **authorized security testing only**. Always obtain proper authorization before testing any API endpoints. Unauthorized testing may be illegal.