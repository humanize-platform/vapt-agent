# 🏆 VAPT Agent - Intelligent API Security Testing

> **MCP's 1st Birthday Hackathon Submission** 🎉  
> *Hosted by Anthropic & Gradio on Hugging Face*  
> [🔗 Hackathon Page](https://huggingface.co/MCP-1st-Birthday)

---

## 📋 Project Overview

**VAPT Agent** is an autonomous, AI-powered **Vulnerability Assessment and Penetration Testing (VAPT)** platform that revolutionizes API security testing. By combining **Anthropic's Claude Agent SDK**, **Postman MCP Server**, **Gradio Web Interface**, and **RAG-based security education**, this project showcases the power of Model Context Protocol (MCP) for building intelligent, context-aware security tools.

### 🎯 What Makes This Special?

This project demonstrates **three powerful MCP integrations**:

1. **🤖 Anthropic Claude SDK** - Powers the core VAPT reasoning agent with Claude Haiku 4.5
2. **📮 Postman MCP Server** - Enables automatic API discovery and OpenAPI specification generation
3. **🛠️ Custom VAPT MCP Server** - Provides specialized security testing tools (SQL injection, XSS, auth testing, etc.)

Combined with a **modern Gradio interface** and **RAG-powered AI tutor** using Chroma vector search, VAPT Agent bridges the gap between automated security testing and developer education.

---

## 🏗️ Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    Gradio Web Interface                         │
│  (Real-time Progress, Visual Dashboard, AI Security Tutor)      │
└────────────────────┬────────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────────┐
│              VAPT Agent Orchestrator                            │
│              (vapt_agent.py)                                    │
└─────┬──────────────────────────────┬────────────────────────────┘
      │                              │
      ▼                              ▼
┌─────────────────────┐    ┌──────────────────────────────────────┐
│  Claude Agent SDK   │    │     MCP Servers (via Claude SDK)     │
│  (Haiku 4.5 Model)  │◄───┤  ┌────────────┐  ┌────────────────┐ │
│                     │    │  │ Postman    │  │ Custom VAPT    │ │
│ • Reasoning         │    │  │ MCP Server │  │ MCP Tools      │ │
│ • Test Planning     │    │  │ (SSE)      │  │ (Local Server) │ │
│ • Report Gen        │    │  └────────────┘  └────────────────┘ │
└─────────────────────┘    └──────────────────────────────────────┘
                                     │
                     ┌───────────────┴───────────────┐
                     ▼                               ▼
              ┌──────────────┐            ┌─────────────────────┐
              │ Postman API  │            │ Target API Endpoint │
              │ • Discovery  │            │ • Security Testing  │
              │ • Schema Gen │            │ • Vuln Detection    │
              └──────────────┘            └─────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                    AI Security Tutor (RAG)                      │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────────────┐   │
│  │ Nebius LLM   │  │ Chroma DB    │  │ Nebius Embeddings  │   │
│  │ (gpt-oss-20b)│◄─┤ Vector Store │◄─┤ (Qwen3-Embed-8B)   │   │
│  └──────────────┘  └──────────────┘  └────────────────────┘   │
│         ▲                   ▲                                   │
│         │                   │                                   │
│         └───────────────────┴─── VAPT Report Context           │
└─────────────────────────────────────────────────────────────────┘
```

### 🔄 How It Works

1. **User Input** → User provides API endpoint via Gradio interface
2. **Discovery** → Claude agent uses **Postman MCP** to discover endpoints and generate OpenAPI spec
3. **Testing** → Agent invokes **Custom VAPT MCP tools** to test for vulnerabilities
4. **Reasoning** → **Claude Haiku 4.5** analyzes results and generates comprehensive security report
5. **Visualization** → Gradio dashboard displays risk scores and severity charts
6. **Education** → User asks questions → **AI Tutor** uses **RAG (Chroma + Nebius embeddings)** to retrieve relevant report sections → **Nebius LLM** generates educational explanations

---

## ✨ Key Features

### 🔒 Comprehensive Security Testing

Automated vulnerability detection powered by Claude's reasoning and custom MCP tools:

- **Injection Attacks**: SQL injection, XSS, path traversal
- **Authentication & Authorization**: Broken auth detection, token validation
- **Rate Limiting**: DoS vulnerability assessment, burst testing (50 requests)
- **CORS Policy**: Origin validation, wildcard detection
- **Security Headers**: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, etc.

### 🎨 Modern Gradio Web Interface

Beautiful, responsive UI built with Gradio featuring:

- **Real-time Progress Streaming** from Claude agent
- **Downloadable Markdown Reports** for audit trails
- **Visual Risk Dashboard** with interactive charts (risk gauge + severity pie chart)
- **Tabbed Interface** for organized information flow
- **Custom CSS Styling** for professional appearance

### 🧠 RAG-Powered AI Security Tutor

**Context Engineering & Retrieval-Augmented Generation (RAG)** implementation:

#### How RAG Works in VAPT Agent:

1. **Document Chunking** (`ai_tutor.py`):
   - Report split into logical sections based on markdown headers (`##`)
   - Large sections auto-chunked to ~2000 characters for optimal retrieval
   - Preserves context boundaries for coherent answers

2. **Vector Embedding** (Nebius + Chroma):
   - Each chunk embedded using **Qwen3-Embedding-8B** (Nebius)
   - Vectors stored in **Chroma** ephemeral in-memory database
   - Index automatically rebuilt when report changes (SHA-256 content hashing)
   - Never reuses old vectors for new reports

3. **Semantic Search**:
   - User question embedded with same model
   - Top-K (default: 4) relevant chunks retrieved via cosine similarity
   - Context passed to LLM for grounded responses

4. **Context Engineering**:
   - System prompt instructs LLM to prioritize retrieved VAPT report context
   - Combines report snippets + optional web search (Tavily)
   - Prevents hallucination by grounding answers in actual findings

**Benefits**:
- ✅ Accurate answers specific to YOUR security report
- ✅ No generic security advice - tailored to actual findings
- ✅ Efficient: Only relevant context sent to LLM (cost-effective)
- ✅ Educational: Explains vulnerabilities in your specific API

### 📮 Postman MCP Integration

Leverages **Postman's official MCP server** (SSE protocol):

- Automatic API endpoint discovery
- OpenAPI/Swagger specification generation
- Request/response schema analysis
- Collection management for organized testing
- Seamless integration via Claude Agent SDK

### 🤖 Anthropic Claude SDK

Core agent powered by **Claude Agent SDK**:

- **Model**: Claude Haiku 4.5 (fast, cost-efficient, high-quality reasoning)
- **Multi-turn Reasoning**: Agent conversations up to 100 turns
- **Tool Orchestration**: Coordinates Postman MCP + Custom VAPT MCP tools
- **Flexible Deployment**: Anthropic API or AWS Bedrock
- **Permission Mode**: Bypass permissions for automated testing

---

## 🎁 Benefits & Impact

### For Security Professionals
- ⚡ **Save Time**: Automate repetitive VAPT tasks
- 📊 **Visual Insights**: Instantly understand risk posture with charts
- 🎓 **Learn On-the-Go**: AI tutor explains findings while you work
- 📄 **Audit-Ready Reports**: Comprehensive markdown reports with evidence

### For Developers
- 🛡️ **Shift-Left Security**: Test APIs during development
- 📚 **Security Education**: Learn secure coding through AI tutor
- 🔧 **Easy Integration**: Simple API endpoint input
- 🚀 **Fast Feedback**: Get results in minutes, not days

### For Organizations
- 💰 **Cost-Effective**: Reduce manual penetration testing costs
- 📈 **Scalable**: Test multiple APIs rapidly
- 📋 **Compliance**: Generate audit-ready security reports
- 🔄 **Continuous Testing**: Integrate into CI/CD pipelines

### Technical Innovation
- 🧩 **MCP Showcase**: Demonstrates multiple MCP server integration
- 🔬 **RAG Best Practices**: Production-ready context engineering
- 🎨 **UX Excellence**: Beautiful, intuitive Gradio interface
- 🔓 **Open Source**: Extensible architecture for custom tools

---

## 🚀 Prerequisites

- **Python 3.10+**
- **[Postman API Key](https://postman.com/settings/api-keys)** - For MCP server access
- **[Anthropic API Key](https://console.anthropic.com/) OR AWS Bedrock** - For Claude Haiku 4.5
- **[Nebius API Key](https://nebius.com/)** - For AI Tutor (optional but recommended)

---

## 📦 Installation

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

---

## ⚙️ Configuration

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
ANTHROPIC_MODEL=global.anthropic.claude-haiku-4-5-20251001-v1:0
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

# Embedding Model for Vector Search (REQUIRED for RAG)
NEBIUS_EMBEDDING_MODEL=Qwen3-Embedding-8B

# --- Optional Web Search ---
# TAVILY_API_KEY=tvly-...
```

---

## 🎮 Usage

### 1. Web Interface (Recommended)

Launch the **Gradio dashboard** for an interactive experience:

```bash
python app.py
```

- Open your browser at `http://localhost:7861`
- Enter the API endpoint and HTTP method
- Watch the real-time progress log
- View the generated report, risk dashboard, and chat with the AI Security Tutor

### 2. Command Line Interface

Run the agent directly from the terminal:

```bash
python vapt_agent.py
```

(Ensure `TEST_API_ENDPOINT` and `TEST_API_METHOD` are set in your `.env` file for CLI usage)

---

## 🔍 Security Tests Performed

The agent uses custom MCP tools (`vapt_tools.py`) to perform:

### 1. **Injection Testing**
- SQL Injection with various payloads (e.g., `' OR '1'='1`)
- XSS (Cross-Site Scripting) detection
- Path traversal attempts (`../../../etc/passwd`)

### 2. **Authentication Testing**
- Endpoint access without credentials
- Authentication bypass attempts
- Token validation and expiration checks

### 3. **Rate Limiting**
- Burst request testing (50 rapid requests)
- 429 status code detection
- DoS vulnerability assessment

### 4. **CORS Policy**
- Origin validation testing
- Wildcard (`*`) detection
- Cross-origin request testing

### 5. **Security Headers**
- `Strict-Transport-Security` (HSTS)
- `X-Content-Type-Options`
- `X-Frame-Options`
- `Content-Security-Policy`
- `X-XSS-Protection`

---

## 📊 Output

The agent generates a comprehensive **Markdown report** saved as `vapt_report_YYYYMMDD_HHMMSS.md` containing:

- **Executive Summary** with risk score
- **Vulnerability Details** (Severity, Description, Evidence, Remediation)
- **Security Headers Analysis**
- **CORS Policy Review**
- **Rate Limiting Assessment**
- **Recommendations** for fixes

---

## 🛠️ Troubleshooting

### Postman API Key Issues
- Get your API key from: https://postman.com/settings/api-keys
- Ensure the key has necessary permissions for collections and environments

### AWS Bedrock Issues
- Verify AWS credentials are correct
- Ensure you have access to Claude models in your region
- Check IAM permissions for Bedrock

### AI Tutor Not Working
- Check `NEBIUS_API_KEY` is set
- Ensure `NEBIUS_EMBEDDING_MODEL` is set to `Qwen3-Embedding-8B` for vector search to work
- Verify `chromadb` is installed: `pip install chromadb`

### Gradio Interface Issues
- Ensure port 7861 is not blocked
- Try clearing browser cache
- Check console logs for errors

---

## 🤝 Contributing

Contributions are welcome! Please follow the existing code structure:

- Keep tools modular in `vapt_tools.py`
- Add configuration in `config.py`
- Update `.env.template` for new variables
- Follow Python best practices (PEP 8)
- Add docstrings for new functions

---

## 📜 License

MIT License - See LICENSE file for details

---

## ⚠️ Disclaimer

This tool is for **authorized security testing only**. Always obtain proper authorization before testing any API endpoints. Unauthorized testing may be illegal and unethical.

---

## 🙏 Acknowledgments

Built for **MCP's 1st Birthday Hackathon** hosted by **Anthropic** and **Gradio**.

**Technologies Used**:
- [Anthropic Claude Agent SDK](https://github.com/anthropics/anthropic-sdk-python)
- [Gradio](https://gradio.app/)
- [Postman MCP Server](https://mcp.postman.com/)
- [Chroma](https://www.trychroma.com/)
- [Nebius Token Factory](https://nebius.com/)

---