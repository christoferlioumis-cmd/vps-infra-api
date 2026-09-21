import os
from sqlalchemy import create_engine, Column, Integer, String, Boolean, ForeignKey, DateTime, UniqueConstraint, func
from sqlalchemy.orm import declarative_base, sessionmaker, relationship
from dotenv import load_dotenv
 
load_dotenv()
 
# Get database URL from environment or default to SQLite for local development
DATABASE_URL = os.getenv("POSTGRES_URL", "sqlite:///./users.db")
 
# connect_args is needed only for SQLite to allow multiple threads
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {}
)
 
# 2. Create the Session Factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
 
# 3. Create the Base class for models
Base = declarative_base()
 
# 4. Define the User Table
class UserDB(Base):
    __tablename__ = "users"
 
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, nullable=True)
    full_name = Column(String, nullable=True)
    hashed_password = Column(String)
    disabled = Column(Boolean, default=False)
    is_admin = Column(Boolean, default=False)
    # Incremented to invalidate every previously issued token (access + refresh)
    # for this user in one shot — no need to store/track individual tokens.
    token_version = Column(Integer, default=0, nullable=False)
    # Login attempt lockout: reset to 0 on any successful login; once it
    # hits MAX_FAILED_LOGIN_ATTEMPTS (in api.py), locked_until gets set
    # and further logins are rejected until that time passes.
    failed_login_attempts = Column(Integer, default=0, nullable=False)
    locked_until = Column(DateTime(timezone=True), nullable=True)
    # Timestamp of the user's most recent successful login (nullable —
    # never set for a user who hasn't logged in yet).
    last_login_at = Column(DateTime(timezone=True), nullable=True)
 
    vehicles = relationship("VehicleDB", back_populates="owner", cascade="all, delete-orphan")
 
 
# 5. Define the Vehicle Table (owned by a user, links to InfluxDB tag "vehicle_id")
class VehicleDB(Base):
    __tablename__ = "vehicles"
 
    id = Column(Integer, primary_key=True, index=True)
    # This is the value used as the InfluxDB "vehicle_id" tag, NOT the DB row id
    vehicle_id = Column(String, unique=True, index=True, nullable=False)
    name = Column(String, nullable=True)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
 
    owner = relationship("UserDB", back_populates="vehicles")
 
    __table_args__ = (UniqueConstraint("vehicle_id", name="uq_vehicle_vehicle_id"),)
 
 
# Table creation and all schema changes now go exclusively through Alembic
# (see alembic/versions/) — nothing in this file creates or alters tables.
# Run `alembic upgrade head` to bring a database up to the current schema.