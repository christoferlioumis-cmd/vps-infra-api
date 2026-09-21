import os
import time
import random
import argparse
from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import SYNCHRONOUS
from dotenv import load_dotenv
 
load_dotenv()
 
# -------- CONFIG --------
INFLUX_URL = os.getenv("INFLUX_URL", "")
INFLUX_TOKEN = os.getenv("INFLUX_TOKEN", "")
INFLUX_ORG = os.getenv("INFLUX_ORG", "")
INFLUX_BUCKET = os.getenv("INFLUX_BUCKET", "")
 
MEASUREMENT = "mqtt_consumer"
 
 
def seed(vehicle_id: str, customer_id: str, hours: int, interval_seconds: int):
    client = InfluxDBClient(url=INFLUX_URL, token=INFLUX_TOKEN, org=INFLUX_ORG)
    write_api = client.write_api(write_options=SYNCHRONOUS)
 
    now = int(time.time())
    total_seconds = hours * 3600
    num_samples = total_seconds // interval_seconds
 
    points = []
    for i in range(num_samples):
        ts = now - (i * interval_seconds)
        point = (
            Point(MEASUREMENT)
            .tag("vehicle_id", vehicle_id)
            .tag("customer_id", customer_id)
            .field("speed", random.randint(0, 120))
            .field("soc", round(random.uniform(0.2, 0.9), 3))
            .field("battery_temp", round(random.uniform(20, 45), 2))
            .time(ts * 1_000_000_000)  # nanoseconds
        )
        points.append(point)
 
    write_api.write(bucket=INFLUX_BUCKET, record=points)
    client.close()
 
    print(f"Seeded {num_samples} samples for vehicle_id='{vehicle_id}' "
          f"(customer_id='{customer_id}') covering the last {hours}h "
          f"(1 sample every {interval_seconds}s)")
 
 
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Seed InfluxDB with test vehicle telemetry.")
    parser.add_argument("--vehicle", required=True, help="vehicle_id tag to write (must already exist in Postgres)")
    parser.add_argument("--customer", required=True, help="customer_id tag to write")
    parser.add_argument("--hours", type=int, default=24, help="How many hours back the data should span (default: 24)")
    parser.add_argument("--interval-seconds", type=int, default=60, help="Seconds between samples (default: 60 = one sample per minute)")
    args = parser.parse_args()
 
    seed(args.vehicle, args.customer, args.hours, args.interval_seconds)
 