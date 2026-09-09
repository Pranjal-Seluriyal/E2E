"""Initial E2EE schema

Revision ID: 001_initial_e2ee_schema
Revises: 
Create Date: 2026-08-23 15:10:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '001_initial_e2ee_schema'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Create devices table
    op.create_table(
        'devices',
        sa.Column('user_id', sa.UUID(), nullable=False),
        sa.Column('device_id', sa.String(length=64), nullable=False),
        sa.Column('device_name', sa.String(length=100), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('last_active_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.PrimaryKeyConstraint('user_id', 'device_id')
    )
    op.create_index('idx_devices_user_id', 'devices', ['user_id'], unique=False)

    # 2. Create device_public_keys table
    op.create_table(
        'device_public_keys',
        sa.Column('user_id', sa.UUID(), nullable=False),
        sa.Column('device_id', sa.String(length=64), nullable=False),
        sa.Column('identity_key', sa.LargeBinary(), nullable=False),
        sa.Column('signed_prekey', sa.LargeBinary(), nullable=False),
        sa.Column('signed_prekey_signature', sa.LargeBinary(), nullable=False),
        sa.Column('signed_prekey_id', sa.Integer(), nullable=False),
        sa.Column('spk_created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(
            ['user_id', 'device_id'], ['devices.user_id', 'devices.device_id'], ondelete='CASCADE'
        ),
        sa.PrimaryKeyConstraint('user_id', 'device_id')
    )

    # 3. Create one_time_prekeys table
    op.create_table(
        'one_time_prekeys',
        sa.Column('id', sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column('user_id', sa.UUID(), nullable=False),
        sa.Column('device_id', sa.String(length=64), nullable=False),
        sa.Column('prekey_id', sa.Integer(), nullable=False),
        sa.Column('prekey', sa.LargeBinary(), nullable=False),
        sa.Column('consumed', sa.Boolean(), server_default=sa.text('false'), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(
            ['user_id', 'device_id'], ['devices.user_id', 'devices.device_id'], ondelete='CASCADE'
        ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('user_id', 'device_id', 'prekey_id', name='unique_user_device_prekey')
    )
    op.create_index(
        'idx_otk_search',
        'one_time_prekeys',
        ['user_id', 'device_id'],
        unique=False,
        postgresql_where=sa.text('consumed = false')
    )

    # 4. Create device_revocations table
    op.create_table(
        'device_revocations',
        sa.Column('user_id', sa.UUID(), nullable=False),
        sa.Column('device_id', sa.String(length=64), nullable=False),
        sa.Column('revoked_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.PrimaryKeyConstraint('user_id', 'device_id')
    )


def downgrade() -> None:
    op.drop_index('idx_otk_search', table_name='one_time_prekeys')
    op.drop_table('one_time_prekeys')
    op.drop_table('device_public_keys')
    op.drop_index('idx_devices_user_id', table_name='devices')
    op.drop_table('devices')
    op.drop_table('device_revocations')
