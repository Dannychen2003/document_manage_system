"""Remove content_hash from Document

Revision ID: 8b606559f079
Revises: 3139e6d16af4
Create Date: 2024-11-20 16:47:07.799918

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '8b606559f079'
down_revision = '3139e6d16af4'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('documents', schema=None) as batch_op:
        batch_op.drop_column('content_hash')

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('documents', schema=None) as batch_op:
        batch_op.add_column(sa.Column('content_hash', sa.VARCHAR(length=64), nullable=True))

    # ### end Alembic commands ###
