"""Baseline the manually managed VA manager schema.

Revision ID: 19b432bf5f98
Revises: 
Create Date: 2026-03-29 21:02:49.111270

"""
from typing import Sequence, Union

revision: str = "19b432bf5f98"
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Record the existing schema as the Alembic baseline.

    This revision intentionally performs no DDL. Existing environments should
    use `alembic stamp head` after confirming the live schema matches the ORM
    models. Future revisions can then capture incremental changes normally.
    """
    pass


def downgrade() -> None:
    """Remove only the Alembic baseline marker."""
    pass
