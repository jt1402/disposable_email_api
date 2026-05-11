"""drop users.stripe_customer_id — Stripe is fully replaced by Polar

Revision ID: b3c8d1a02fe5
Revises: f29a6e1bbd02
Create Date: 2026-05-11 15:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "b3c8d1a02fe5"
down_revision: Union[str, None] = "f29a6e1bbd02"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # The column was kept around during the Polar migration as a safety belt
    # for rollback. We're past that window now; drop it.
    op.drop_index("ix_users_stripe_customer_id", table_name="users", if_exists=True)
    op.drop_column("users", "stripe_customer_id")


def downgrade() -> None:
    op.add_column(
        "users",
        sa.Column("stripe_customer_id", sa.String(length=64), nullable=True),
    )
    op.create_index(
        "ix_users_stripe_customer_id",
        "users",
        ["stripe_customer_id"],
        unique=True,
    )
