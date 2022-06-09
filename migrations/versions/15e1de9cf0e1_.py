"""empty message

Revision ID: 15e1de9cf0e1
Revises: 0b59a863c671
Create Date: 2022-06-09 10:50:38.066690

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '15e1de9cf0e1'
down_revision = '0b59a863c671'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('user_type',
    sa.Column('user_type_id', sa.Integer(), nullable=False),
    sa.Column('type', sa.String(length=20), nullable=False),
    sa.PrimaryKeyConstraint('user_type_id'),
    sa.UniqueConstraint('type')
    )
    op.create_table('user',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('fname', sa.String(length=20), nullable=False),
    sa.Column('lname', sa.String(length=20), nullable=False),
    sa.Column('gender', sa.String(length=10), nullable=False),
    sa.Column('email', sa.String(length=120), nullable=False),
    sa.Column('phone', sa.String(length=20), nullable=False),
    sa.Column('age', sa.String(length=10), nullable=False),
    sa.Column('address', sa.String(length=200), nullable=False),
    sa.Column('password', sa.String(length=60), nullable=False),
    sa.Column('u_type', sa.String(length=10), nullable=False),
    sa.Column('has_premium', sa.String(length=10), nullable=False),
    sa.Column('user_type_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['user_type_id'], ['user_type.user_type_id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('email'),
    sa.UniqueConstraint('phone')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('user')
    op.drop_table('user_type')
    # ### end Alembic commands ###
