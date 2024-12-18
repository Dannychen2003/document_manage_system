"""Add archive_reason to Document

Revision ID: d6da2213039f
Revises: 8e269deaf3a3
Create Date: 2024-12-05 19:41:27.767179

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'd6da2213039f'
down_revision = '8e269deaf3a3'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('documents', schema=None) as batch_op:
        batch_op.add_column(sa.Column('archive_reason', sa.String(length=500), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('documents', schema=None) as batch_op:
        batch_op.drop_column('archive_reason')

    # ### end Alembic commands ###
