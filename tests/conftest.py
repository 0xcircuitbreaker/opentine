"""Shared pytest configuration and fixtures."""


def pytest_addoption(parser):
    parser.addoption("--provider", default="anthropic", help="Provider name for live tests")
