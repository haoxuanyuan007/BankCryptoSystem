"""empty message

Revision ID: 0d4c6acbedda
Revises: 6fc3e88a2a16
Create Date: 2025-03-01 19:08:42.157025

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '0d4c6acbedda'
down_revision = '6fc3e88a2a16'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('message', schema=None) as batch_op:
        batch_op.add_column(sa.Column('signature', sa.Text(), nullable=True))

    with op.batch_alter_table('transaction', schema=None) as batch_op:
        batch_op.add_column(sa.Column('signature', sa.Text(), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('transaction', schema=None) as batch_op:
        batch_op.drop_column('signature')

    with op.batch_alter_table('message', schema=None) as batch_op:
        batch_op.drop_column('signature')

    # ### end Alembic commands ###
