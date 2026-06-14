# driftcore/memory/__init__.py
# Two-stage memory system for driftcore-os
# Proven approach: surprise for storage, resonance for retrieval.
#
# Also re-exports legacy MemoryFS and IntegrityChecker for backward
# compatibility with RecoverySystem and AgentRuntime (raw logging +
# quarantine layer). Both layers are intended to be used together:
#   - MemoryFS  → append-only raw log, summaries, quarantine
#   - DriftcoreMemory → queryable two-stage surprise/resonance store

from .memory_core import DriftcoreMemory, MemoryItem, SurpriseStore, ResonanceRetriever
from .memory_fs import MemoryFS
from .integrity import IntegrityChecker

__all__ = [
    "DriftcoreMemory",
    "MemoryItem",
    "SurpriseStore",
    "ResonanceRetriever",
    "MemoryFS",
    "IntegrityChecker",
]
