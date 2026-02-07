from sqlalchemy import Column, Integer, String

from ..db.connection import Base


class Repo(Base):
    __tablename__ = "repos"

    id = Column(Integer, primary_key=True)
    owner = Column(String(256), nullable=False)
    name = Column(String(256), nullable=False)
