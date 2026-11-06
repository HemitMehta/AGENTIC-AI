#!/bin/bash
# init_databases.sh
# Initialize all required PostgreSQL databases

set -e

psql -U user postgres <<EOSQL
  CREATE DATABASE did_registry;
  CREATE DATABASE trust_anchors;
  CREATE DATABASE vc_issuance;
  CREATE DATABASE revocation;
  CREATE DATABASE wallets;
  CREATE DATABASE layer2;
  CREATE DATABASE layer3;
EOSQL

echo "All databases initialized successfully"
