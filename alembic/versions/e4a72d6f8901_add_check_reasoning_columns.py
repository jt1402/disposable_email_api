"""add risk_level, confidence_level, disposable to checks

Revision ID: e4a72d6f8901
Revises: d1f4a91b3c20
Create Date: 2026-05-06 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "e4a72d6f8901"
down_revision: Union[str, None] = "d1f4a91b3c20"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("checks", sa.Column("risk_level", sa.String(length=16), nullable=True))
    op.add_column(
        "checks", sa.Column("confidence_level", sa.String(length=16), nullable=True)
    )
    op.add_column("checks", sa.Column("disposable", sa.Boolean(), nullable=True))


def downgrade() -> None:
    op.drop_column("checks", "disposable")
    op.drop_column("checks", "confidence_level")
    op.drop_column("checks", "risk_level")
