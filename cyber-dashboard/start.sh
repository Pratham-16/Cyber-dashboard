#!/bin/bash
# start.sh — launches both the backend (Node/Express) and frontend (Python http.server)
# for the OSINT dashboard, and stops both cleanly on Ctrl+C.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$SCRIPT_DIR/backend"
FRONTEND_DIR="$SCRIPT_DIR/frontend"
FRONTEND_PORT=8080
BACKEND_PORT=5000

echo "Starting backend (Node.js on port $BACKEND_PORT)..."
cd "$BACKEND_DIR"
node server.js &
BACKEND_PID=$!

echo "Starting frontend (Python http.server on port $FRONTEND_PORT)..."
cd "$FRONTEND_DIR"
python3 -m http.server $FRONTEND_PORT &
FRONTEND_PID=$!

cleanup() {
  echo ""
  echo "Stopping servers..."
  kill "$BACKEND_PID" 2>/dev/null
  kill "$FRONTEND_PID" 2>/dev/null
  wait "$BACKEND_PID" 2>/dev/null
  wait "$FRONTEND_PID" 2>/dev/null
  echo "Stopped."
  exit 0
}

trap cleanup SIGINT SIGTERM

echo ""
echo "Dashboard running:"
echo "  Frontend: http://localhost:$FRONTEND_PORT"
echo "  Backend:  http://localhost:$BACKEND_PORT"
echo ""
echo "Press Ctrl+C to stop both servers."

wait
