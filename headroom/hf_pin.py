"""Centralised Hugging Face revision pinning.

Supply-chain hardening: every Hub download (models, tokenizers, datasets,
ONNX artifacts) should request a specific immutable commit ``revision``
rather than the mutable ``main`` branch. Without a pin, a compromised or
hijacked repo can silently swap weights/code on the next cache miss.

The pins below are the commit SHAs that ``main`` resolved to at the time
they were recorded, so pinning is behaviour-preserving — the same bytes
that would have been fetched today are now locked. Operators can override
any pin (e.g. to adopt a newer reviewed revision) via an environment
variable without touching code:

    HEADROOM_HF_REV__<repo_id>

where ``repo_id`` has ``/`` and ``-`` replaced with ``__`` and ``_``
respectively, e.g.::

    HEADROOM_HF_REV__answerdotai__ModernBERT_base=<sha>

``pinned_revision`` returns ``None`` for any repo not in the registry,
which preserves the previous "track latest" behaviour for repos we cannot
pin (e.g. gated datasets) while keeping the ``revision=`` keyword present
at every call site.
"""

from __future__ import annotations

import os

__all__ = ["pinned_revision"]

# repo_id -> pinned commit SHA. Recorded from the live Hub API; refresh
# deliberately (and review the diff) when intentionally adopting a new
# upstream revision.
_PINNED_REVISIONS: dict[str, str] = {
    # --- Production runtime models ---
    "answerdotai/ModernBERT-base": "8949b909ec900327062f0ebf497f51aef5e6f0c8",
    "Qdrant/all-MiniLM-L6-v2-onnx": "5f1b8cd78bc4fb444dd171e59b18f3a3af89a079",
    "sentence-transformers/all-MiniLM-L6-v2": "1110a243fdf4706b3f48f1d95db1a4f5529b4d41",
    "all-MiniLM-L6-v2": "1110a243fdf4706b3f48f1d95db1a4f5529b4d41",
    "google/siglip-base-patch16-224": "7fd15f0689c79d79e38b1c2e2e2370a7bf2761ed",
    "chopratejas/technique-router-onnx": "27b0b4bfa510a1cff66d888072c0b807082721a8",
    "chopratejas/siglip-image-encoder-onnx": "d0a9fbd66d4bd8c761bff592d44831f7c2ae184e",
    "chopratejas/technique-router": "639f08ab1fac0a0eb888bbeb80e752dbf8a780c1",
    "chopratejas/kompress-v2-base": "b1563631b35bfdcee37587ad530147497d820d4c",
    # --- Evaluation datasets ---
    "hotpotqa/hotpot_qa": "1908d6afbbead072334abe2965f91bd2709910ab",
    "google-research-datasets/natural_questions": "e8103d566bef4154c2c12b17c6095ec5275840cc",
    "microsoft/ms_marco": "a47ee7aae8d7d466ba15f9f0bfac3b3681087b3a",
    "rajpurkar/squad_v2": "3ffb306f725f7d2ce8394bc1873b24868140c412",
    "deepmind/narrativeqa": "2e643e7363944af1c33a652d1c87320d0871c4e4",
    "allenai/scrapinghub-article-extraction-benchmark": "f74b11e8b2e38f3828c3052622d108a22de53319",
}


def pinned_revision(repo_id: str) -> str | None:
    """Return the pinned commit SHA for ``repo_id``.

    Resolution order: ``HEADROOM_HF_REV__<repo_id>`` environment override,
    then the static registry, then ``None`` (track latest) for unknown repos.
    """
    if not repo_id:
        return None
    env_key = "HEADROOM_HF_REV__" + repo_id.replace("/", "__").replace("-", "_")
    override = os.environ.get(env_key)
    if override:
        return override.strip()
    return _PINNED_REVISIONS.get(repo_id)
