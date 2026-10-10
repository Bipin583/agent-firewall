"""Persistence for the optional HTTP API.

SQLAlchemy 2.0 async models. The core engine and the Claude Code hook do NOT
import this module -- it is only pulled in by the ``[api]`` extra, so the hook
keeps its minimal dependency surface (see config.py).

We store a *redacted* summary of each decision, never the raw tool input, mirror-
ing the audit log's discipline.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from sqlalchemy import JSON, DateTime, Integer, String, Text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class DecisionRecord(Base):
    """One persisted evaluation. Fields mirror :class:`SecurityDecision` plus the
    request context needed to query history. No raw payloads are stored."""

    __tablename__ = "decisions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    decision_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    request_id: Mapped[str] = mapped_column(String(64), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    tool_name: Mapped[str] = mapped_column(String(128), index=True)
    decision: Mapped[str] = mapped_column(String(16), index=True)
    risk_score: Mapped[int] = mapped_column(Integer, index=True)
    risk_level: Mapped[str] = mapped_column(String(16))
    agent_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    session_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    environment: Mapped[str] = mapped_column(String(32), index=True)
    matched_policies: Mapped[list[str]] = mapped_column(JSON, default=list)
    matched_rules: Mapped[list[str]] = mapped_column(JSON, default=list)
    explanation: Mapped[str] = mapped_column(Text, default="")
    redacted_summary: Mapped[str] = mapped_column(Text, default="")

    def as_dict(self) -> dict[str, Any]:
        return {
            "decision_id": self.decision_id,
            "request_id": self.request_id,
            "created_at": self.created_at.isoformat(),
            "tool_name": self.tool_name,
            "decision": self.decision,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "agent_id": self.agent_id,
            "session_id": self.session_id,
            "environment": self.environment,
            "matched_policies": self.matched_policies,
            "matched_rules": self.matched_rules,
            "explanation": self.explanation,
            "redacted_summary": self.redacted_summary,
        }


def _ensure_sqlite_dir(db_url: str) -> None:
    """A sqlite file URL needs its parent directory to exist first."""
    marker = "sqlite+aiosqlite:///"
    if db_url.startswith(marker):
        rel = db_url[len(marker):]
        if rel and rel != ":memory:":
            Path(rel).expanduser().parent.mkdir(parents=True, exist_ok=True)


def create_engine(db_url: str) -> AsyncEngine:
    _ensure_sqlite_dir(db_url)
    return create_async_engine(db_url, future=True)


def make_sessionmaker(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False)


async def init_models(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
