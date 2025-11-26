"""
VAPT Tools - Custom security testing tools for API vulnerability assessment.

This module contains the custom VAPT tool implementation for performing
comprehensive security tests on API endpoints.
"""

import json
from typing import Dict, List, Any, Optional
from datetime import datetime
from pydantic import BaseModel, Field

from claude_agent_sdk import create_sdk_mcp_server, tool


# ============================================================================
# Data Models
# ============================================================================


class VAPTTestInput(BaseModel):
    """Input schema for VAPT security testing tool."""

    endpoint: str = Field(
        description="The API endpoint URL to test (e.g., https://api.example.com/v1/users)"
    )
    method: str = Field(
        default="GET", description="HTTP method (GET, POST, PUT, DELETE, PATCH)"
    )
    test_types: List[str] = Field(
        default=["injection", "auth", "rate_limit", "cors"],
        description="Types of security tests to perform: injection, auth, rate_limit, cors, headers, ssl",
    )
    headers: Optional[Dict[str, str]] = Field(
        default=None, description="Optional headers to include in requests"
    )
    body: Optional[str] = Field(
        default=None, description="Optional request body for POST/PUT/PATCH requests"
    )


class VAPTTestResult(BaseModel):
    """Result schema for VAPT security testing."""

    endpoint: str
    test_type: str
    severity: str  # critical, high, medium, low, info
    status: str  # vulnerable, secure, warning
    description: str
    recommendation: str
    evidence: Optional[Dict[str, Any]] = None


# ============================================================================
# Security Testing Functions
# ============================================================================


async def test_sql_injection(
    session, endpoint: str, method: str, headers: Dict[str, str], body: str
) -> List[VAPTTestResult]:
    """Test for SQL injection vulnerabilities."""
    results = []

    injection_payloads = [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' UNION SELECT NULL--",
        "admin'--",
        "1' AND '1'='1",
    ]

    for payload in injection_payloads:
        test_url = f"{endpoint}?q={payload}" if method == "GET" else endpoint
        test_body = body or json.dumps({"input": payload})

        try:
            import aiohttp

            async with session.request(
                method,
                test_url,
                headers=headers,
                data=test_body if method in ["POST", "PUT", "PATCH"] else None,
                timeout=aiohttp.ClientTimeout(total=10),
                ssl=False,
            ) as response:
                response_text = await response.text()

                # Check for SQL error messages
                error_indicators = [
                    "sql",
                    "mysql",
                    "sqlite",
                    "postgresql",
                    "oracle",
                    "syntax error",
                    "unclosed quotation",
                    "database error",
                ]

                if any(
                    indicator in response_text.lower() for indicator in error_indicators
                ):
                    results.append(
                        VAPTTestResult(
                            endpoint=endpoint,
                            test_type="SQL Injection",
                            severity="critical",
                            status="vulnerable",
                            description=f"Endpoint vulnerable to SQL injection with payload: {payload}",
                            recommendation="Use parameterized queries/prepared statements. Implement input validation and sanitization.",
                            evidence={
                                "payload": payload,
                                "status_code": response.status,
                            },
                        )
                    )
                    break  # Found vulnerability, no need to test more payloads

        except Exception as e:
            results.append(
                VAPTTestResult(
                    endpoint=endpoint,
                    test_type="SQL Injection Test",
                    severity="info",
                    status="warning",
                    description=f"Could not complete injection test: {str(e)}",
                    recommendation="Ensure endpoint is accessible for testing",
                    evidence={"error": str(e)},
                )
            )
            break

    return results


async def test_xss(
    session, endpoint: str, method: str, headers: Dict[str, str], body: str
) -> List[VAPTTestResult]:
    """Test for Cross-Site Scripting (XSS) vulnerabilities."""
    results = []

    xss_payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "javascript:alert('XSS')",
    ]

    for payload in xss_payloads:
        test_url = f"{endpoint}?input={payload}" if method == "GET" else endpoint
        test_body = body or json.dumps({"input": payload})

        try:
            import aiohttp

            async with session.request(
                method,
                test_url,
                headers=headers,
                data=test_body if method in ["POST", "PUT", "PATCH"] else None,
                timeout=aiohttp.ClientTimeout(total=10),
                ssl=False,
            ) as response:
                response_text = await response.text()

                # Check if payload is reflected without sanitization
                if payload in response_text:
                    results.append(
                        VAPTTestResult(
                            endpoint=endpoint,
                            test_type="XSS (Cross-Site Scripting)",
                            severity="high",
                            status="vulnerable",
                            description=f"Endpoint reflects unsanitized input: {payload}",
                            recommendation="Implement proper output encoding and Content-Security-Policy headers.",
                            evidence={
                                "payload": payload,
                                "status_code": response.status,
                            },
                        )
                    )
                    break

        except Exception as e:
            results.append(
                VAPTTestResult(
                    endpoint=endpoint,
                    test_type="XSS Test",
                    severity="info",
                    status="warning",
                    description=f"Could not complete XSS test: {str(e)}",
                    recommendation="Ensure endpoint is accessible for testing",
                    evidence={"error": str(e)},
                )
            )
            break

    return results


async def test_authentication(
    session, endpoint: str, method: str, headers: Dict[str, str]
) -> List[VAPTTestResult]:
    """Test authentication and authorization controls."""
    results = []

    # Test without authentication headers
    try:
        import aiohttp

        test_headers = headers.copy() if headers else {}
        test_headers.pop("Authorization", None)
        test_headers.pop("X-API-Key", None)

        async with session.request(
            method,
            endpoint,
            headers=test_headers,
            timeout=aiohttp.ClientTimeout(total=10),
            ssl=False,
        ) as response:
            if response.status == 200:
                results.append(
                    VAPTTestResult(
                        endpoint=endpoint,
                        test_type="Authentication",
                        severity="high",
                        status="vulnerable",
                        description="Endpoint accessible without authentication",
                        recommendation="Implement proper authentication (OAuth2, JWT, API Keys). Return 401/403 for unauthenticated requests.",
                        evidence={"status_code": response.status},
                    )
                )
            elif response.status in [401, 403]:
                results.append(
                    VAPTTestResult(
                        endpoint=endpoint,
                        test_type="Authentication",
                        severity="info",
                        status="secure",
                        description="Endpoint properly requires authentication",
                        recommendation="Continue monitoring authentication implementation",
                        evidence={"status_code": response.status},
                    )
                )
    except Exception as e:
        results.append(
            VAPTTestResult(
                endpoint=endpoint,
                test_type="Authentication Test",
                severity="info",
                status="warning",
                description=f"Could not complete auth test: {str(e)}",
                recommendation="Verify endpoint accessibility",
                evidence={"error": str(e)},
            )
        )

    return results


async def test_rate_limiting(
    session, endpoint: str, method: str, headers: Dict[str, str]
) -> List[VAPTTestResult]:
    """Test rate limiting implementation."""
    results = []
    rate_limit_requests = 50
    rate_limit_exceeded = False

    try:
        import aiohttp

        for i in range(rate_limit_requests):
            async with session.request(
                method,
                endpoint,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=5),
                ssl=False,
            ) as response:
                if response.status == 429:
                    rate_limit_exceeded = True
                    results.append(
                        VAPTTestResult(
                            endpoint=endpoint,
                            test_type="Rate Limiting",
                            severity="info",
                            status="secure",
                            description=f"Rate limiting detected after {i+1} requests",
                            recommendation="Rate limiting is properly configured",
                            evidence={"requests_before_limit": i + 1},
                        )
                    )
                    break

        if not rate_limit_exceeded:
            results.append(
                VAPTTestResult(
                    endpoint=endpoint,
                    test_type="Rate Limiting",
                    severity="medium",
                    status="vulnerable",
                    description=f"No rate limiting detected after {rate_limit_requests} requests",
                    recommendation="Implement rate limiting to prevent abuse and DoS attacks",
                    evidence={"requests_sent": rate_limit_requests},
                )
            )
    except Exception as e:
        results.append(
            VAPTTestResult(
                endpoint=endpoint,
                test_type="Rate Limiting Test",
                severity="info",
                status="warning",
                description=f"Could not complete rate limit test: {str(e)}",
                recommendation="Verify endpoint stability",
                evidence={"error": str(e)},
            )
        )

    return results


async def test_cors_policy(session, endpoint: str, method: str) -> List[VAPTTestResult]:
    """Test CORS policy configuration."""
    results = []

    cors_headers = {
        "Origin": "https://evil.com",
        "Access-Control-Request-Method": method,
        "Access-Control-Request-Headers": "X-Custom-Header",
    }

    try:
        import aiohttp

        async with session.options(
            endpoint,
            headers=cors_headers,
            timeout=aiohttp.ClientTimeout(total=10),
            ssl=False,
        ) as response:
            cors_allow_origin = response.headers.get("Access-Control-Allow-Origin", "")

            if cors_allow_origin == "*":
                results.append(
                    VAPTTestResult(
                        endpoint=endpoint,
                        test_type="CORS Policy",
                        severity="medium",
                        status="vulnerable",
                        description="CORS allows requests from any origin (*)",
                        recommendation="Restrict CORS to specific trusted domains. Avoid using wildcard (*) in production.",
                        evidence={"access_control_allow_origin": cors_allow_origin},
                    )
                )
            elif cors_allow_origin:
                results.append(
                    VAPTTestResult(
                        endpoint=endpoint,
                        test_type="CORS Policy",
                        severity="info",
                        status="secure",
                        description=f"CORS properly configured for origin: {cors_allow_origin}",
                        recommendation="Review allowed origins periodically",
                        evidence={"access_control_allow_origin": cors_allow_origin},
                    )
                )
    except Exception as e:
        results.append(
            VAPTTestResult(
                endpoint=endpoint,
                test_type="CORS Policy Test",
                severity="info",
                status="warning",
                description=f"Could not complete CORS test: {str(e)}",
                recommendation="Verify CORS configuration manually",
                evidence={"error": str(e)},
            )
        )

    return results


async def test_security_headers(
    session, endpoint: str, method: str, headers: Dict[str, str]
) -> List[VAPTTestResult]:
    """Test security headers implementation."""
    results = []

    try:
        import aiohttp

        async with session.request(
            method,
            endpoint,
            headers=headers,
            timeout=aiohttp.ClientTimeout(total=10),
            ssl=False,
        ) as response:
            security_headers = {
                "Strict-Transport-Security": "HSTS missing",
                "X-Content-Type-Options": "X-Content-Type-Options missing",
                "X-Frame-Options": "X-Frame-Options missing",
                "Content-Security-Policy": "CSP missing",
                "X-XSS-Protection": "X-XSS-Protection missing",
            }

            missing_headers = []
            for header, message in security_headers.items():
                if header not in response.headers:
                    missing_headers.append(header)

            if missing_headers:
                results.append(
                    VAPTTestResult(
                        endpoint=endpoint,
                        test_type="Security Headers",
                        severity="medium",
                        status="vulnerable",
                        description=f"Missing security headers: {', '.join(missing_headers)}",
                        recommendation="Implement all recommended security headers to protect against common attacks",
                        evidence={"missing_headers": missing_headers},
                    )
                )
            else:
                results.append(
                    VAPTTestResult(
                        endpoint=endpoint,
                        test_type="Security Headers",
                        severity="info",
                        status="secure",
                        description="All recommended security headers present",
                        recommendation="Continue monitoring header configuration",
                        evidence={"status": "all_headers_present"},
                    )
                )
    except Exception as e:
        results.append(
            VAPTTestResult(
                endpoint=endpoint,
                test_type="Security Headers Test",
                severity="info",
                status="warning",
                description=f"Could not complete headers test: {str(e)}",
                recommendation="Verify endpoint response headers",
                evidence={"error": str(e)},
            )
        )

    return results


# ============================================================================
# Main VAPT Tool
# ============================================================================


@tool(
    name="vapt_security_test",
    description="Performs comprehensive API security testing including SQL injection, XSS, authentication, rate limiting, CORS, and security headers validation. Returns a detailed JSON report with vulnerabilities and remediation recommendations.",
    input_schema={
        "type": "object",
        "properties": {
            "endpoint": {
                "type": "string",
                "description": "The API endpoint URL to test (e.g., https://api.example.com/v1/users)",
            },
            "method": {
                "type": "string",
                "description": "HTTP method (GET, POST, PUT, DELETE, PATCH)",
                "default": "GET",
            },
            "test_types": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Types of security tests to perform: injection, auth, rate_limit, cors, headers",
                "default": ["injection", "auth", "rate_limit", "cors", "headers"],
            },
            "headers": {
                "type": "object",
                "description": "Optional HTTP headers as key-value pairs",
                "default": None,
            },
            "body": {
                "type": "string",
                "description": "Optional request body for POST/PUT/PATCH requests",
                "default": None,
            },
        },
        "required": ["endpoint"],
    },
)
async def vapt_security_test(args: Dict[str, Any]) -> Dict[str, Any]:
    """
    Custom VAPT tool for API security testing.

    Performs various security tests on API endpoints including:
    - SQL Injection tests
    - XSS (Cross-Site Scripting) tests
    - Authentication/Authorization bypasses
    - Rate limiting checks
    - CORS policy validation
    - Security headers assessment

    Args:
        args: Dictionary containing endpoint, method, test_types, headers, and body

    Returns:
        Dictionary with content containing the test results JSON report
    """
    import aiohttp

    # Extract parameters from args dict
    endpoint = args["endpoint"]
    method = args.get("method", "GET")
    test_types = args.get("test_types")
    headers = args.get("headers")
    body = args.get("body")

    if test_types is None:
        test_types = ["injection", "auth", "rate_limit", "cors", "headers"]

    if headers is None:
        headers = {}

    all_results: List[VAPTTestResult] = []

    async with aiohttp.ClientSession() as session:

        # Run tests based on specified test types
        if "injection" in test_types:
            sql_results = await test_sql_injection(
                session, endpoint, method, headers, body
            )
            all_results.extend(sql_results)

            xss_results = await test_xss(session, endpoint, method, headers, body)
            all_results.extend(xss_results)

        if "auth" in test_types:
            auth_results = await test_authentication(session, endpoint, method, headers)
            all_results.extend(auth_results)

        if "rate_limit" in test_types:
            rate_results = await test_rate_limiting(session, endpoint, method, headers)
            all_results.extend(rate_results)

        if "cors" in test_types:
            cors_results = await test_cors_policy(session, endpoint, method)
            all_results.extend(cors_results)

        if "headers" in test_types:
            header_results = await test_security_headers(
                session, endpoint, method, headers
            )
            all_results.extend(header_results)

    # Format results as JSON report
    report = {
        "endpoint": endpoint,
        "method": method,
        "timestamp": datetime.now().isoformat(),
        "tests_performed": test_types,
        "total_vulnerabilities": len(
            [r for r in all_results if r.status == "vulnerable"]
        ),
        "results": [r.dict() for r in all_results],
        "summary": {
            "critical": len([r for r in all_results if r.severity == "critical"]),
            "high": len([r for r in all_results if r.severity == "high"]),
            "medium": len([r for r in all_results if r.severity == "medium"]),
            "low": len([r for r in all_results if r.severity == "low"]),
            "info": len([r for r in all_results if r.severity == "info"]),
        },
    }

    report_json = json.dumps(report, indent=2)

    # Return in MCP tool format
    return {"content": [{"type": "text", "text": report_json}]}


# ============================================================================
# MCP Server Creation
# ============================================================================


def create_vapt_mcp_server():
    """Create and return the VAPT MCP server instance."""
    return create_sdk_mcp_server(
        name="VAPTToolServer",
        version="1.0.0",
        tools=[vapt_security_test],
    )
