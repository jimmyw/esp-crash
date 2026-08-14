"""persist mcp oauth store

Revision ID: 48bdaa31d2f9
Revises: 6beade548d43
Create Date: 2026-08-14 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = '48bdaa31d2f9'
down_revision: Union[str, Sequence[str], None] = '6beade548d43'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'mcp_oauth_client',
        sa.Column('client_id', sa.Text(), nullable=False),
        sa.Column('data', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column('created_at', sa.TIMESTAMP(), server_default=sa.text('now()'), nullable=True),
        sa.PrimaryKeyConstraint('client_id'),
    )
    op.create_table(
        'mcp_access_token',
        sa.Column('token', sa.Text(), nullable=False),
        sa.Column('client_id', sa.Text(), nullable=False),
        sa.Column('expires_at', sa.BigInteger(), nullable=True),
        sa.Column('data', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column('created_at', sa.TIMESTAMP(), server_default=sa.text('now()'), nullable=True),
        sa.PrimaryKeyConstraint('token'),
    )
    op.create_index(
        'idx_mcp_access_token_expires_at', 'mcp_access_token', ['expires_at'], unique=False
    )
    op.create_table(
        'mcp_refresh_token',
        sa.Column('token', sa.Text(), nullable=False),
        sa.Column('client_id', sa.Text(), nullable=False),
        sa.Column('data', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column('created_at', sa.TIMESTAMP(), server_default=sa.text('now()'), nullable=True),
        sa.PrimaryKeyConstraint('token'),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table('mcp_refresh_token')
    op.drop_index('idx_mcp_access_token_expires_at', table_name='mcp_access_token')
    op.drop_table('mcp_access_token')
    op.drop_table('mcp_oauth_client')
