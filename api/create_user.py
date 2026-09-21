import os
import sys
import argparse
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import IntegrityError
from dotenv import load_dotenv

# Import your existing models and logic
from database import UserDB, VehicleDB
from api import get_password_hash

load_dotenv()

# docker-compose passes this as 'postgresql://user:pass@postgres/dbname'
DATABASE_URL = os.getenv("POSTGRES_URL")

if not DATABASE_URL:
    print("Error: POSTGRES_URL environment variable is not set.")
    sys.exit(1)

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def create_user(username, password, vehicle_id=None):
    db = SessionLocal()
    try:
        # Table schema is managed by Alembic (run `alembic upgrade head`
        # before using this script on a fresh database).

        user = db.query(UserDB).filter(UserDB.username == username).first()
        if user:
            print(f"Skipping: User '{username}' already exists.")
        else:
            user = UserDB(
                username=username,
                hashed_password=get_password_hash(password),
                disabled=False
            )
            db.add(user)
            db.commit()
            db.refresh(user)
            print(f"Success: User '{username}' created in Postgres.")

        if vehicle_id:
            existing_vehicle = db.query(VehicleDB).filter(VehicleDB.vehicle_id == vehicle_id).first()
            if existing_vehicle:
                print(f"Skipping: Vehicle '{vehicle_id}' is already registered "
                      f"(owner: user id {existing_vehicle.owner_id}).")
            else:
                vehicle = VehicleDB(vehicle_id=vehicle_id, owner_id=user.id)
                db.add(vehicle)
                try:
                    db.commit()
                    print(f"Success: Vehicle '{vehicle_id}' linked to user '{username}'.")
                except IntegrityError:
                    db.rollback()
                    print(f"Database Error: could not link vehicle '{vehicle_id}'.")
                    sys.exit(1)
    except Exception as e:
        print(f"Database Error: {e}")
        sys.exit(1)
    finally:
        db.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--user", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--vehicle", required=False, help="Vehicle ID to link to this user (matches InfluxDB tag 'vehicle_id')")
    args = parser.parse_args()

    create_user(args.user, args.password, args.vehicle)