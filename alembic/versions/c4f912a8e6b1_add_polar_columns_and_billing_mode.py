"""add polar columns and billing_mode to users

Revision ID: c4f912a8e6b1
Revises: 782a0d5c8b8a
Create Date: 2026-05-04 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "c4f912a8e6b1"
down_revision: Union[str, None] = "782a0d5c8b8a"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("polar_customer_id", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "users",
        sa.Column("polar_subscription_id", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "users",
        sa.Column(
            "billing_mode",
            sa.String(length=16),
            server_default="bundles",
            nullable=False,
        ),
    )
    op.create_unique_constraint(
        "uq_users_polar_customer_id", "users", ["polar_customer_id"]
    )
    op.create_unique_constraint(
        "uq_users_polar_subscription_id", "users", ["polar_subscription_id"]
    )
    op.create_index(
        "ix_users_polar_customer_id", "users", ["polar_customer_id"]
    )
    op.create_index(
        "ix_users_polar_subscription_id", "users", ["polar_subscription_id"]
    )


def downgrade() -> None:
    op.drop_index("ix_users_polar_subscription_id", table_name="users")
    op.drop_index("ix_users_polar_customer_id", table_name="users")
    op.drop_constraint("uq_users_polar_subscription_id", "users", type_="unique")
    op.drop_constraint("uq_users_polar_customer_id", "users", type_="unique")
    op.drop_column("users", "billing_mode")
    op.drop_column("users", "polar_subscription_id")
    op.drop_column("users", "polar_customer_id")
