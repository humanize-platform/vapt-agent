# VAPT Agent - API Security Testing with Claude

A comprehensive vulnerability assessment and penetration testing (VAPT) agent that uses Claude Agent SDK with Postman MCP server for automated API security testing.

## Features

- **Automated Security Testing**: Performs comprehensive security assessments including:
  - SQL Injection detection
  - XSS (Cross-Site Scripting) detection
  - Authentication/Authorization testing
  - Rate limiting verification
  - CORS policy validation
  - Security headers assessment

- **Postman Integration**: Uses Postman MCP server (SSE) for automatic API specification creation and testing

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

### Environment Variables

Create a `.env` file with the following variables:

```properties
# AWS Bedrock (set to 1 to use Bedrock, 0 for Anthropic API)
CLAUDE_CODE_USE_BEDROCK=1
AWS_ACCESS_KEY_ID=your_access_key
AWS_SECRET_ACCESS_KEY=your_secret_key
AWS_REGION=us-east-1

# Model selection
ANTHROPIC_MODEL=us.anthropic.claude-sonnet-4-20250514-v1:0

# Postman API key (get from https://postman.com/settings/api-keys)
POSTMAN_API_KEY=your_postman_api_key

# Test API configuration
TEST_API_ENDPOINT=https://api.example.com/v1/users
TEST_API_METHOD=GET
TEST_API_KEY=optional_bearer_token
```

### Postman MCP Server Configuration

The agent connects to Postman's hosted MCP server via SSE:

```json
{
  "type": "sse",
  "url": "https://mcp.postman.com/mcp",
  "headers": {
    "Authorization": "Bearer ${POSTMAN_API_KEY}"
# Test a specific endpoint
asyncio.run(run_vapt_agent(
    api_endpoint="https://api.example.com/v1/users",
    method="GET",
    headers={
        "Authorization": "Bearer your-token",
        "Content-Type": "application/json"
    }
))
```

## Security Tests Performed

### 1. **Injection Testing**
- SQL Injection with various payloads
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
- Wildcard (*) detection
- Cross-origin request testing

### 5. **Security Headers**
- Strict-Transport-Security (HSTS)
- X-Content-Type-Options
- X-Frame-Options
- Content-Security-Policy
- X-XSS-Protection

## Output

The agent generates a comprehensive JSON report saved as `vapt_report_YYYYMMDD_HHMMSS.json`:

```json
{
  "endpoint": "https://api.example.com/v1/users",
  "method": "GET",
  "timestamp": "2025-01-15T10:30:00",
  "tests_performed": ["injection", "auth", "rate_limit", "cors", "headers"],
  "total_vulnerabilities": 3,
  "results": [
    {
      "test_type": "SQL Injection",
      "severity": "critical",
      "status": "vulnerable",
      "description": "...",
      "recommendation": "...",
      "evidence": {...}
    }
  ],
  "summary": {
    "critical": 1,
    "high": 2,
    "medium": 0,
    "low": 0,
    "info": 5
  }
}
```

## AWS Bedrock vs Anthropic API

### Using AWS Bedrock
```properties
CLAUDE_CODE_USE_BEDROCK=1
AWS_ACCESS_KEY_ID=...
AWS_SECRET_ACCESS_KEY=...
AWS_REGION=us-east-1
ANTHROPIC_MODEL=us.anthropic.claude-sonnet-4-20250514-v1:0
```

### Using Anthropic API
```properties
CLAUDE_CODE_USE_BEDROCK=0
ANTHROPIC_API_KEY=sk-ant-...
ANTHROPIC_MODEL=claude-sonnet-4-20250514
```

## Troubleshooting

### Postman API Key Issues
- Get your API key from: https://postman.com/settings/api-keys
- Ensure the key has necessary permissions

### AWS Bedrock Issues
- Verify AWS credentials are correct
- Ensure you have access to Claude models in your region
- Check AWS region supports the specified model

### Timeout Errors
- Increase `TIMEOUT_SECONDS` in `.env` for slow APIs
- Reduce test intensity for rate limit tests

## Contributing

Contributions are welcome! Please follow the existing code structure:
- Keep tools modular in `vapt_tools.py`
- Add configuration in `config.py`
- Update `.env.template` for new variables

## License

MIT License

## Disclaimer

This tool is for authorized security testing only. Always obtain proper authorization before testing any API endpoints. Unauthorized testing may be illegal.