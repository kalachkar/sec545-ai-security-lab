from harness.providers.base import Provider, ProviderResult


def get_provider(name: str) -> Provider:
    if name == "claude_cli":
        from harness.providers.claude_cli import ClaudeCliProvider
        return ClaudeCliProvider()
    if name == "anthropic_api":
        from harness.providers.anthropic_api import AnthropicApiProvider
        return AnthropicApiProvider()
    if name == "databricks":
        from harness.providers.databricks import DatabricksProvider
        return DatabricksProvider()
    raise SystemExit(f"unknown provider {name!r} (claude_cli | anthropic_api | databricks)")
