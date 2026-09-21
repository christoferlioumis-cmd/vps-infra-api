FROM python:3.12-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Apply any pending database migrations, then run FastAPI with Uvicorn.
# This is what keeps the schema in sync automatically on every start —
# fresh databases get built up from alembic/versions/, existing ones get
# only the migrations they're missing. Nothing calls create_all() anymore.
CMD ["sh", "-c", "alembic upgrade head && uvicorn api:app --host 0.0.0.0 --port 8000"]