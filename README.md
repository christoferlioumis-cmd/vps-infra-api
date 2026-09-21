# vps-infra
# VPS Infrastructure API

Dockerized FastAPI service for vehicle telemetry.

The project uses:

- **FastAPI** for the REST API and Swagger documentation
- **PostgreSQL** for users and vehicle ownership
- **InfluxDB** for vehicle telemetry data
- **JWT Bearer tokens** for authentication
- **Docker Compose** to run all services

> The telemetry created by `seed_data.py` is test data generated with Python `random`; it does not come from real vehicle sensors.

## Architecture

```text
Client / Swagger UI
        ↓
     FastAPI API
      ↙       ↘
PostgreSQL   InfluxDB
Users &      Telemetry:
Vehicles     speed, SOC, battery temperature