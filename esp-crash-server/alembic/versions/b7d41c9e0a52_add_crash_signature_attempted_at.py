"""add crash signature_attempted_at

Records that a signature was computed for a crash's current dump, whether or
not one could be produced. Without it the backfill in app/routes/cron.py
cannot distinguish "not yet tried" from "tried, no parseable backtrace", so
the unparseable rows are re-selected every tick forever - and because that
query is ordered `crash_id DESC`, the newest such rows sat permanently at the
head of the queue and starved ~45k signable crashes behind them.

Left NULL for existing rows on purpose: rows that already have a signature
never match the backfill filter, and the rows that don't have one genuinely
still need an attempt. So this migration is a metadata-only ADD COLUMN plus
one partial index - no table rewrite, no data backfill.

Revision ID: b7d41c9e0a52
Revises: 9c3e1b7a54d2
Create Date: 2026-09-03 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b7d41c9e0a52'
down_revision: Union[str, Sequence[str], None] = '9c3e1b7a54d2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column(
        'crash',
        sa.Column('signature_attempted_at', sa.TIMESTAMP(timezone=True), nullable=True),
    )
    # Matches the backfill query's WHERE clause exactly, so it acts as a
    # work queue that shrinks to nothing as the backlog drains.
    op.create_index(
        'idx_crash_signature_pending',
        'crash',
        ['crash_id'],
        unique=False,
        postgresql_where=sa.text(
            "dump IS NOT NULL AND signature IS NULL "
            "AND signature_attempted_at IS NULL"
        ),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index('idx_crash_signature_pending', table_name='crash')
    op.drop_column('crash', 'signature_attempted_at')
