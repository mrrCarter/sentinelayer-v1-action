from sqlalchemy import Column, Integer, String, DateTime
from datetime import datetime

from ..db.connection import Base


class Run(Base):
    __tablename__ = "runs"

    id = Column(Integer, primary_key=True)
    run_id = Column(String(64), unique=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
