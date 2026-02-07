from sqlalchemy import Column, Integer, String

from ..db.connection import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    github_id = Column(String(64), unique=True, nullable=False)
    username = Column(String(256), nullable=False)
