import os
import sys
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool
from dotenv import load_dotenv

# Make sure "import database" (from api/) works regardless of where
# alembic is invoked from.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

load_dotenv()

from database import Base  # noqa: E402  (must come after sys.path fix)

# Alembic Config object, gives access to values in alembic.ini
config = context.config

# Use the exact same env var as the rest of the app (api.py/database.py),
# so there is only ever one place that defines "which database are we using".
db_url = os.getenv("POSTGRES_URL", "sqlite:///./users.db")
config.set_main_option("sqlalchemy.url", db_url)

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# target_metadata is what makes `alembic revision --autogenerate` work:
# Alembic diffs this against the live database schema to generate migrations.
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Generate SQL script without a live DB connection (rarely used here)."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Apply migrations directly against the live database (normal usage)."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()