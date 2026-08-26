"""Adapter registry. An unknown vault name falls back to `discard`, never to a leak."""

from __future__ import annotations

from omp.adapters.age import AgeAdapter
from omp.adapters.base import FORBIDDEN_METHODS, StoreError, StoreResult, VaultAdapter
from omp.adapters.discard import DiscardAdapter
from omp.adapters.doppler import DopplerAdapter
from omp.config import Config

REGISTRY: dict[str, type[VaultAdapter]] = {
    DiscardAdapter.name: DiscardAdapter,
    DopplerAdapter.name: DopplerAdapter,
    AgeAdapter.name: AgeAdapter,
}


def build(config: Config) -> VaultAdapter:
    """Build the configured adapter. Any construction error degrades to `discard`."""
    adapter_class = REGISTRY.get(config.vault)
    if adapter_class is None:
        return DiscardAdapter()
    try:
        adapter = adapter_class(**config.options) if config.options else adapter_class()
    except (StoreError, TypeError):
        return DiscardAdapter()
    if not adapter.available():
        return DiscardAdapter()
    return adapter


__all__ = [
    "FORBIDDEN_METHODS",
    "REGISTRY",
    "StoreError",
    "StoreResult",
    "VaultAdapter",
    "build",
]
