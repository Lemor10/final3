"""create activity_log table

Revision ID: 947a50332eda
Revises: fix_username_not_null
Create Date: 2026-01-07 23:46:33.119578

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '947a50332eda'
down_revision = 'fix_username_not_null'
branch_labels = None
depends_on = None


def upgrade():
    pass


def downgrade():
    pass
