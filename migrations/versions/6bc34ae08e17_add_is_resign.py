"""Add is_resign

Revision ID: 6bc34ae08e17
Revises: b8e8f366754a
Create Date: 2024-12-07 20:48:20.059179

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '6bc34ae08e17'
down_revision = 'b8e8f366754a'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('documents', schema=None) as batch_op:
        batch_op.add_column(sa.Column('reassign_reason', sa.String(length=500), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('documents', schema=None) as batch_op:
        batch_op.drop_column('reassign_reason')

    # ### end Alembic commands ###
