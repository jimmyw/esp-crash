"""add tags

Revision ID: cea7c0eff075
Revises: 0d0fe6fc2c74
Create Date: 2026-08-13 12:45:09.225396

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'cea7c0eff075'
down_revision: Union[str, Sequence[str], None] = '0d0fe6fc2c74'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table('tag',
    sa.Column('tag_id', sa.Integer(), nullable=False),
    sa.Column('project_name', sa.Text(), nullable=False),
    sa.Column('name', sa.Text(), nullable=False),
    sa.Column('description', sa.Text(), nullable=True),
    sa.PrimaryKeyConstraint('tag_id'),
    sa.UniqueConstraint('project_name', 'name', name='uq_tag_project_name_name'),
    )
    op.create_index('idx_tag_project_name', 'tag', ['project_name'], unique=False)

    op.create_table('crash_tag',
    sa.Column('crash_id', sa.Integer(), nullable=False),
    sa.Column('tag_id', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['crash_id'], ['crash.crash_id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['tag_id'], ['tag.tag_id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('crash_id', 'tag_id'),
    )
    op.create_index('idx_crash_tag_tag_id', 'crash_tag', ['tag_id'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index('idx_crash_tag_tag_id', table_name='crash_tag')
    op.drop_table('crash_tag')
    op.drop_index('idx_tag_project_name', table_name='tag')
    op.drop_table('tag')
