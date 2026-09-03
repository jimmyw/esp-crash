"""add project_settings toolchain

Revision ID: 9c3e1b7a54d2
Revises: 4bee415e957c
Create Date: 2026-09-03 10:00:00.000000

Names the debugger toolchain to use for a project's crashes. Nullable, and
NULL is a valid steady state: a project with no toolchain set simply has no
interactive debug session offered, since there is no safe default (guessing
would mean handing gdb an ELF built for another architecture).

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '9c3e1b7a54d2'
down_revision: Union[str, Sequence[str], None] = '4bee415e957c'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column('project_settings', sa.Column('toolchain', sa.Text(), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('project_settings', 'toolchain')
