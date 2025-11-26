"""
Configuration module for VAPT Agent.

This module handles all configuration loading from environment variables
and provides a centralized config object.
"""

import os
from typing import Optional
from dotenv import load_dotenv

load_dotenv(override=True)


class VAPTConfig:
    """Configuration class for VAPT Agent."""

    def __init__(self):
        """Initialize configuration from environment variables."""

        # ====================================================================
        # AWS Configuration
        # ====================================================================
        self.use_bedrock = os.getenv("CLAUDE_CODE_USE_BEDROCK", "0") == "1"
        self.aws_access_key_id = os.getenv("AWS_ACCESS_KEY_ID", "")
        self.aws_secret_access_key = os.getenv("AWS_SECRET_ACCESS_KEY", "")
        self.aws_region = os.getenv("AWS_REGION", "us-east-1")

        # ====================================================================
        # Model Configuration
        # ====================================================================
        if self.use_bedrock:
            # Default to Bedrock model identifier
            # default_model = "global.anthropic.claude-sonnet-4-5-20250929-v1:0"
            default_model = "global.anthropic.claude-haiku-4-5-20251001-v1:0"
        else:
            # Default to Anthropic API model
            default_model = "claude-sonnet-4-20250514"

        self.model_name = os.getenv("ANTHROPIC_MODEL", default_model)

        # ====================================================================
        # Postman Configuration
        # ====================================================================
        self.postman_api_key = os.getenv("POSTMAN_API_KEY", "")

        # ====================================================================
        # Test API Configuration
        # ====================================================================
        self.test_api_endpoint = os.getenv(
            "TEST_API_ENDPOINT", "https://jsonplaceholder.typicode.com/posts"
        )
        self.test_api_method = os.getenv("TEST_API_METHOD", "GET")
        self.test_api_key = os.getenv("TEST_API_KEY", "")

        # ====================================================================
        # Agent Configuration
        # ====================================================================
        self.max_turns = int(os.getenv("MAX_TURNS", "100"))
        self.timeout_seconds = int(os.getenv("TIMEOUT_SECONDS", "600"))
        self.max_retries = int(os.getenv("MAX_RETRIES", "3"))

        # Validate required configuration
        self._validate()

    def _validate(self):
        """Validate required configuration values."""
        errors = []

        if not self.postman_api_key:
            errors.append("POSTMAN_API_KEY is required")

        if self.use_bedrock:
            if not self.aws_access_key_id:
                errors.append("AWS_ACCESS_KEY_ID is required when using Bedrock")
            if not self.aws_secret_access_key:
                errors.append("AWS_SECRET_ACCESS_KEY is required when using Bedrock")

        if errors:
            raise ValueError(
                "Configuration validation failed:\n"
                + "\n".join(f"  - {e}" for e in errors)
            )

    def to_dict(self):
        """Return configuration as dictionary (excluding sensitive data)."""
        return {
            "use_bedrock": self.use_bedrock,
            "aws_region": self.aws_region,
            "model_name": self.model_name,
            "test_api_endpoint": self.test_api_endpoint,
            "test_api_method": self.test_api_method,
            "max_turns": self.max_turns,
            "timeout_seconds": self.timeout_seconds,
            "max_retries": self.max_retries,
        }

    def __repr__(self):
        """String representation of configuration."""
        return f"VAPTConfig({self.to_dict()})"
