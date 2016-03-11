#!/bin/bash

set -e

export PROJECT_ROOT="$(dirname "$0")"

cd "$PROJECT_ROOT"

mvn clean install -DskipITs

mvn verify site
