from sqlalchemy import Column, String, DateTime, ForeignKey, UUID
from sqlalchemy.sql import func
from app.models.base import Base

class Device(Base):
    __tablename__ = "devices"

    user_id = Column(UUID(as_uuid=True), nullable=False, primary_key=True)
    device_id = Column(String(64), nullable=False, primary_key=True)
    device_name = Column(String(100), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    last_active_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)


class DeviceRevocation(Base):
    __tablename__ = "device_revocations"

    user_id = Column(UUID(as_uuid=True), nullable=False, primary_key=True)
    device_id = Column(String(64), nullable=False, primary_key=True)
    revoked_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
