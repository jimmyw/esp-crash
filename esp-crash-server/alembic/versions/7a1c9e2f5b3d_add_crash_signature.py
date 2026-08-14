"""add crash signature

Revision ID: 7a1c9e2f5b3d
Revises: 48bdaa31d2f9
Create Date: 2026-08-14 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '7a1c9e2f5b3d'
down_revision: Union[str, Sequence[str], None] = '48bdaa31d2f9'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column('crash', sa.Column('signature', sa.Text(), nullable=True))
    op.create_index('idx_crash_signature', 'crash', ['signature'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index('idx_crash_signature', table_name='crash')
    op.drop_column('crash', 'signature')
