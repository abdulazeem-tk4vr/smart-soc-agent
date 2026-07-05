# Ported from soc_defender.
"""Standalone Smart SOC Agent package."""

from .agent import SmartSocAgent, build_agent

__all__ = ["SmartSocAgent", "__version__", "build_agent"]
__version__ = "0.1.0"
