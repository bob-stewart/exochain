#!/bin/bash
set -e
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    CREATE DATABASE livesafe;
    GRANT ALL PRIVILEGES ON DATABASE livesafe TO exochain;
EOSQL
