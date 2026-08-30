"""Loaders for real, externally-labelled corpora.

The synthetic benchmark measures the scheduler under dynamics this project
chose. That is useful for isolating the scheduling question, and useless as
evidence that the result survives contact with reality. These loaders exist to
answer the second question, on data collected and labelled by somebody else.

A loader returns :class:`~attest.datasets.base.Timeline` objects; everything
after that - the risk model, the four policies, the four metrics, the bootstrap
- is the same code path the synthetic benchmark uses, so the two are directly
comparable rather than merely similar.
"""

from .base import Timeline, fit_scorer, split_entities, to_sessions

__all__ = ["Timeline", "fit_scorer", "split_entities", "to_sessions"]
