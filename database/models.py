import uuid
from typing import Optional, List
from sqlalchemy import text, ForeignKey
from sqlalchemy.orm import DeclarativeBase, mapped_column, Mapped, relationship
from sqlalchemy.dialects.postgresql import UUID, VARCHAR, TEXT, TIMESTAMP, ARRAY


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

    messages: Mapped[List["Message"]] = relationship(back_populates='user',
                                                     cascade='all, delete-orphan')


class File(Base):
    __tablename__ = 'files'

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    filename: Mapped[str] = mapped_column()
    mime: Mapped[str] = mapped_column()
    created_at = mapped_column(TIMESTAMP, server_default=text("CURRENT_TIMESTAMP"))
    contents: Mapped[str] = mapped_column(TEXT, nullable=False)


class Message(Base):
    __tablename__ = 'messages'

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    send_by: Mapped[uuid.UUID] = mapped_column(ForeignKey('users.id'))
    contents: Mapped[str] = mapped_column(TEXT)
    attachments: Mapped[List[uuid.UUID]] = mapped_column(ARRAY(UUID), nullable=True)
    send_at = mapped_column(TIMESTAMP, server_default=text("CURRENT_TIMESTAMP"))

    user: Mapped["User"] = relationship(back_populates='messages')
    file = relationship('File',
                        primaryjoin='File.id == any_(foreign(Message.attachments))',
                        uselist=True)
