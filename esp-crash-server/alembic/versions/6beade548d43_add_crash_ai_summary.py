"""add crash ai_summary

Revision ID: 6beade548d43
Revises: cea7c0eff075
Create Date: 2026-08-13 14:01:53.910116

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '6beade548d43'
down_revision: Union[str, Sequence[str], None] = 'cea7c0eff075'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column('crash', sa.Column('ai_summary', sa.Text(), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('crash', 'ai_summary')
