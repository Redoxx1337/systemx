# backend/models.py
"""SQLAlchemy models for SystemX.
We use PostgreSQL (or SQLite for dev) and store:
- User (id, username, email, hashed_password, is_admin, created_at)
- SearchRequest (id, user_id, service, query, result_json, created_at)
- Service (id, name, description, logo_path, enabled)
"""

import enum
from datetime import datetime

from sqlalchemy import (JSON, Boolean, Column, DateTime, Enum, ForeignKey,
                        Integer, String, Text)
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


class ServiceEnum(str, enum.Enum):
    VK = "vk"
    DADATA = "dadata"
    DEPSEARCH = "depsearch"
    NETSPY = "netspy"
    SEETG = "seetg"
    JITLER = "jitler"
    IPINFO = "ipinfo"


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False, index=True)
    email = Column(String(120), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    is_admin = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    requests = relationship("SearchRequest", back_populates="user")


class SearchRequest(Base):
    __tablename__ = "search_requests"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    service = Column(Enum(ServiceEnum), nullable=False)
    query = Column(String(255), nullable=False)
    result_json = Column(JSON)  # raw response from service
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="requests")


class Service(Base):
    __tablename__ = "services"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(50), unique=True, nullable=False)
    description = Column(Text, nullable=True)
    logo_path = Column(String(255), nullable=True)  # relative to /static/img
    enabled = Column(Boolean, default=True)

    def as_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "logo_path": self.logo_path,
            "enabled": self.enabled,
        }
