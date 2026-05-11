"""collapse verify_manually into allow_with_flag

Revision ID: f29a6e1bbd02
Revises: e4a72d6f8901
Create Date: 2026-05-11 12:00:00.000000

The verify_manually recommendation is removed from the API. Existing rows
that used it become allow_with_flag — the dev contract is the same: route
through your verification step. The verify_manually counter on domain_stats
is folded into allow_with_flag and dropped.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "f29a6e1bbd02"
down_revision: Union[str, None] = "e4a72d6f8901"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Rewrite past verdicts on the audit log.
    op.execute(
        "UPDATE checks SET recommendation = 'allow_with_flag' "
        "WHERE recommendation = 'verify_manually'"
    )

    # 2. Fold the counter on domain_stats into allow_with_flag, then drop it.
    op.execute(
        "UPDATE domain_stats "
        "SET allow_with_flag = COALESCE(allow_with_flag, 0) + COALESCE(verify_manually, 0), "
        "    last_recommendation = CASE WHEN last_recommendation = 'verify_manually' "
        "                               THEN 'allow_with_flag' ELSE last_recommendation END"
    )
    op.drop_column("domain_stats", "verify_manually")


def downgrade() -> None:
    # Best-effort: re-add the column but data fold is one-way. Old rows that
    # were verify_manually are now allow_with_flag with no way to distinguish.
    op.add_column(
        "domain_stats",
        sa.Column("verify_manually", sa.BigInteger(), nullable=False, server_default="0"),
    )
