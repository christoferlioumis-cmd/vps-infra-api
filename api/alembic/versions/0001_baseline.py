"""baseline: users + vehicles tables matching current production schema

This migration represents the schema as it already exists in the running
database (built up over time via manual ALTER TABLE commands during
development). It does not change anything on a database that already has
these tables — it exists so Alembic has a starting point to track future
changes from.

Revision ID: 0001
Revises:
Create Date: 2026-07-31

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), primary_key=True, index=True),
        sa.Column("username", sa.String(), unique=True, index=True),
        sa.Column("email", sa.String(), nullable=True),
        sa.Column("full_name", sa.String(), nullable=True),
        sa.Column("hashed_password", sa.String(), nullable=True),
        sa.Column("disabled", sa.Boolean(), server_default=sa.false()),
        sa.Column("is_admin", sa.Boolean(), server_default=sa.false()),
        sa.Column("token_version", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("failed_login_attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
    )

    op.create_table(
        "vehicles",
        sa.Column("id", sa.Integer(), primary_key=True, index=True),
        sa.Column("vehicle_id", sa.String(), nullable=False, index=True),
        sa.Column("name", sa.String(), nullable=True),
        sa.Column("owner_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("vehicle_id", name="uq_vehicle_vehicle_id"),
    )


def downgrade() -> None:
    op.drop_table("vehicles")
    op.drop_table("users")