import uuid
from typing import Optional
from sqlalchemy import text
from sqlalchemy.orm import DeclarativeBase, mapped_column, Mapped
from sqlalchemy.dialects.postgresql import UUID, VARCHAR, INTEGER, BOOLEAN, TEXT, TIMESTAMP, DATE


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = 'users'
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(VARCHAR(32), unique=True)
    bio: Mapped[Optional[str]] = mapped_column(TEXT, nullable=True)
    online: Mapped[bool] = mapped_column(server_default=text('false'))
    last_online = mapped_column(TIMESTAMP, server_default=text("CURRENT_TIMESTAMP"))
    password: Mapped[str] = mapped_column(VARCHAR(256), nullable=False)
