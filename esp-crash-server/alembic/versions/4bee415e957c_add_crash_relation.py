"""add crash_relation

Revision ID: 4bee415e957c
Revises: f4a9024e4afb
Create Date: 2026-08-17 11:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '4bee415e957c'
down_revision: Union[str, Sequence[str], None] = 'f4a9024e4afb'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'crash_relation',
        sa.Column('project_name', sa.Text(), nullable=False),
        sa.Column('signature', sa.Text(), nullable=False),
        sa.Column('ai_title', sa.Text(), nullable=True),
        sa.Column('ai_summary', sa.Text(), nullable=True),
        sa.Column('created_at', sa.TIMESTAMP(), server_default=sa.text('now()'), nullable=False),
        sa.PrimaryKeyConstraint('project_name', 'signature'),
    )

    op.create_table(
        'crash_relation_tag',
        sa.Column('project_name', sa.Text(), nullable=False),
        sa.Column('signature', sa.Text(), nullable=False),
        sa.Column('tag_id', sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(['tag_id'], ['tag.tag_id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(
            ['project_name', 'signature'],
            ['crash_relation.project_name', 'crash_relation.signature'],
            ondelete='CASCADE',
        ),
        sa.PrimaryKeyConstraint('project_name', 'signature', 'tag_id'),
    )
    op.create_index('idx_crash_relation_tag_tag_id', 'crash_relation_tag', ['tag_id'])

    # One relation row per existing signatured group, seeded from its most
    # recent crash's ai_title/ai_summary (NULL/NULL if never reviewed) -
    # same "latest wins" rule the Relations page already uses.
    op.execute("""
        INSERT INTO crash_relation (project_name, signature, ai_title, ai_summary)
        SELECT DISTINCT ON (project_name, signature) project_name, signature, ai_title, ai_summary
        FROM crash
        WHERE signature IS NOT NULL
        ORDER BY project_name, signature, date DESC
    """)

    # Dedup crash_tag into the new junction. Tags on unsignatured crashes
    # (no signature -> no relation to attach to) are dropped here.
    op.execute("""
        INSERT INTO crash_relation_tag (project_name, signature, tag_id)
        SELECT DISTINCT c.project_name, c.signature, ct.tag_id
        FROM crash_tag ct JOIN crash c ON c.crash_id = ct.crash_id
        WHERE c.signature IS NOT NULL
        ON CONFLICT DO NOTHING
    """)

    op.create_foreign_key(
        'fk_crash_crash_relation', 'crash', 'crash_relation',
        ['project_name', 'signature'], ['project_name', 'signature'],
    )
    op.drop_column('crash', 'ai_title')
    op.drop_column('crash', 'ai_summary')
    op.drop_table('crash_tag')


def downgrade() -> None:
    """Downgrade schema. Structural only - does not restore data."""
    op.add_column('crash', sa.Column('ai_summary', sa.Text(), nullable=True))
    op.add_column('crash', sa.Column('ai_title', sa.Text(), nullable=True))
    op.drop_constraint('fk_crash_crash_relation', 'crash', type_='foreignkey')

    op.create_table(
        'crash_tag',
        sa.Column('crash_id', sa.Integer(), nullable=False),
        sa.Column('tag_id', sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(['crash_id'], ['crash.crash_id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['tag_id'], ['tag.tag_id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('crash_id', 'tag_id'),
    )
    op.create_index('idx_crash_tag_tag_id', 'crash_tag', ['tag_id'])

    op.drop_table('crash_relation_tag')
    op.drop_table('crash_relation')
