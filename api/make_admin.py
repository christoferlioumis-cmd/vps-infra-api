"""
Promote an existing user to admin (or create a new admin user directly).
 
Usage:
    docker compose exec api python make_admin.py --user chris
    docker compose exec api python make_admin.py --user newadmin --password adminpass123 --create
"""
import argparse
import sys
from database import SessionLocal, UserDB
from api import get_password_hash
 
 
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--user", required=True, help="Username to promote (or create) as admin")
    parser.add_argument("--password", required=False, help="Required only when using --create")
    parser.add_argument("--create", action="store_true", help="Create the user if they don't exist yet")
    args = parser.parse_args()
 
    # Table schema is managed by Alembic (run `alembic upgrade head`
    # before using this script on a fresh database).
    db = SessionLocal()

    try:
        user = db.query(UserDB).filter(UserDB.username == args.user).first()

        if user is None:
            if not args.create:
                print(f"User '{args.user}' does not exist. Use --create to make a new admin user.")
                sys.exit(1)
            if not args.password:
                print("--password is required when using --create.")
                sys.exit(1)

            user = UserDB(
                username=args.user,
                hashed_password=get_password_hash(args.password),
                is_admin=True,
                disabled=False,
            )
            db.add(user)
            db.commit()
            print(f"Created new admin user '{args.user}'.")
        else:
            user.is_admin = True
            if args.password:
                user.hashed_password = get_password_hash(args.password)
            db.commit()
            if args.password:
                print(f"User '{args.user}' promoted to admin and password updated.")
            else:
                print(f"User '{args.user}' promoted to admin.")
    finally:
        db.close()


if __name__ == "__main__":
    main()