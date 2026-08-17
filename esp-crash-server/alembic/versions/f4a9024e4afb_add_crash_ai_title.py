"""add crash ai_title

Revision ID: f4a9024e4afb
Revises: 7a1c9e2f5b3d
Create Date: 2026-08-17 10:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'f4a9024e4afb'
down_revision: Union[str, Sequence[str], None] = '7a1c9e2f5b3d'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column('crash', sa.Column('ai_title', sa.Text(), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('crash', 'ai_title')
