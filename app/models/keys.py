from sqlalchemy import Column, String, DateTime, ForeignKey, Integer, LargeBinary, Boolean, BigInteger, ForeignKeyConstraint, UUID
from sqlalchemy.sql import func
from app.models.base import Base

class DevicePublicKey(Base):
    __tablename__ = "device_public_keys"

    user_id = Column(UUID(as_uuid=True), nullable=False, primary_key=True)  # Mapped to match foreign key structure
    device_id = Column(String(64), nullable=False, primary_key=True)
    identity_key = Column(LargeBinary, nullable=False)  # Public Identity Key (IK_pub)
    signed_prekey = Column(LargeBinary, nullable=False)  # Public Signed Prekey (SPK_pub)
    signed_prekey_signature = Column(LargeBinary, nullable=False)  # SPK Signature signed with IK
    signed_prekey_id = Column(Integer, nullable=False)
    spk_created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    __table_args__ = (
        ForeignKeyConstraint(
            ['user_id', 'device_id'],
            ['devices.user_id', 'devices.device_id'],
            ondelete="CASCADE"
        ),
    )


class OneTimePrekey(Base):
    __tablename__ = "one_time_prekeys"

    id = Column(BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True)
    user_id = Column(UUID(as_uuid=True), nullable=False)
    device_id = Column(String(64), nullable=False)
    prekey_id = Column(Integer, nullable=False)
    prekey = Column(LargeBinary, nullable=False)  # Public One-Time Prekey (OPK_pub)
    consumed = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    __table_args__ = (
        ForeignKeyConstraint(
            ['user_id', 'device_id'],
            ['devices.user_id', 'devices.device_id'],
            ondelete="CASCADE"
        ),
    )
