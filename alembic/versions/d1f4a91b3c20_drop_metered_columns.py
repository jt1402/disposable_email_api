"""drop billing_mode and polar_subscription_id

Revision ID: d1f4a91b3c20
Revises: c4f912a8e6b1
Create Date: 2026-05-04 18:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "d1f4a91b3c20"
down_revision: Union[str, None] = "c4f912a8e6b1"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.drop_index("ix_users_polar_subscription_id", table_name="users")
    op.drop_constraint("uq_users_polar_subscription_id", "users", type_="unique")
    op.drop_column("users", "polar_subscription_id")
    op.drop_column("users", "billing_mode")


def downgrade() -> None:
    op.add_column(
        "users",
        sa.Column(
            "billing_mode",
            sa.String(length=16),
            server_default="bundles",
            nullable=False,
        ),
    )
    op.add_column(
        "users",
        sa.Column("polar_subscription_id", sa.String(length=64), nullable=True),
    )
    op.create_unique_constraint(
        "uq_users_polar_subscription_id", "users", ["polar_subscription_id"]
    )
    op.create_index(
        "ix_users_polar_subscription_id", "users", ["polar_subscription_id"]
    )
