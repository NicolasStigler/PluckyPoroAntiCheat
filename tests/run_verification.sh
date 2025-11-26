#!/bin/bash

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo "Building project..."
cargo build --release

if [ $? -ne 0 ]; then
    echo -e "${RED}Build failed${NC}"
    exit 1
fi

echo "Compiling victim..."
gcc tests/victim.c -o tests/victim

AGENT_BIN="./target/release/plucky-poro-anti-cheat"
VICTIM_BIN="./tests/victim"
LOG_FILE="agent.log"

# Clean up previous runs
sudo pkill -f "plucky-poro-anti-cheat"
sudo pkill -f "victim"
rm -f $LOG_FILE

echo "Starting Agent with Victim ($VICTIM_BIN)..."
# Run agent in background, redirect stdout/stderr to log file
# We use stdbuf to disable buffering so we see logs immediately
sudo RUST_LOG=info stdbuf -o0 -e0 $AGENT_BIN --executable $VICTIM_BIN > $LOG_FILE 2>&1 &
AGENT_PID=$!

echo "Waiting for agent to initialize..."
sleep 5

# Extract Victim PID from logs
# Log format: "Spawned target process ./tests/victim with PID: 12345"
VICTIM_PID=$(grep "Spawned target process" $LOG_FILE | awk '{print $NF}')

if [ -z "$VICTIM_PID" ]; then
    echo -e "${RED}Failed to extract Victim PID from logs.${NC}"
    cat $LOG_FILE
    sudo kill $AGENT_PID
    exit 1
fi

echo -e "${GREEN}Victim PID detected: $VICTIM_PID${NC}"

echo "----------------------------------------------------------------"
echo "Running Test Case 1: PTRACE_ATTACH (Anti-Debugging)"
echo "----------------------------------------------------------------"

python3 tests/attacker_ptrace.py $VICTIM_PID
RET_CODE=$?

if [ $RET_CODE -eq 0 ]; then
    echo -e "${GREEN}[PASS] PTRACE_ATTACH was blocked.${NC}"
else
    echo -e "${RED}[FAIL] PTRACE_ATTACH was NOT blocked or script failed.${NC}"
fi

# Check agent logs for the alert
echo "Checking Agent Logs for Alert..."
if grep -q "SECURITY ALERT: Type=PTRACE" $LOG_FILE; then
    echo -e "${GREEN}[PASS] Agent logged the PTRACE attempt.${NC}"
else
    echo -e "${RED}[FAIL] Agent did NOT log the PTRACE attempt.${NC}"
fi

echo "----------------------------------------------------------------"
echo "Running Test Case 2: process_vm_readv (Memory Isolation)"
echo "----------------------------------------------------------------"

python3 tests/attacker_vm_read.py $VICTIM_PID
RET_CODE=$?

if [ $RET_CODE -eq 0 ]; then
    echo -e "${GREEN}[PASS] process_vm_readv was blocked.${NC}"
else
    echo -e "${RED}[FAIL] process_vm_readv was NOT blocked or script failed.${NC}"
fi

# Check agent logs for the alert
echo "Checking Agent Logs for Alert..."
if grep -q "SECURITY ALERT: Type=VM_READ" $LOG_FILE; then
    echo -e "${GREEN}[PASS] Agent logged the VM_READ attempt.${NC}"
else
    echo -e "${RED}[FAIL] Agent did NOT log the VM_READ attempt.${NC}"
fi

echo "----------------------------------------------------------------"
echo "Running Test Case 3: LD_PRELOAD execve (Execution Integrity)"
echo "----------------------------------------------------------------"

# Trigger the victim to perform execve with LD_PRELOAD
echo "Sending SIGUSR1 to Victim ($VICTIM_PID) to trigger LD_PRELOAD execve..."
sudo kill -SIGUSR1 $VICTIM_PID

# Give it a moment to log
sleep 2

# Check logs for victim's confirmation of block
if grep -q "execve blocked with EPERM (Success)" $LOG_FILE; then
    echo -e "${GREEN}[PASS] LD_PRELOAD execve was blocked (Victim confirmed).${NC}"
else
    echo -e "${RED}[FAIL] LD_PRELOAD execve was NOT blocked or not attempted.${NC}"
fi

# Check agent logs for the alert
if grep -q "SECURITY ALERT: Type=EXEC" $LOG_FILE; then
    echo -e "${GREEN}[PASS] Agent logged the EXEC attempt.${NC}"
else
    echo -e "${RED}[FAIL] Agent did NOT log the EXEC attempt.${NC}"
fi

echo "----------------------------------------------------------------"
echo "Cleaning up..."
sudo kill $AGENT_PID
# Victim should be killed by agent, but ensure it's gone
sudo kill $VICTIM_PID 2>/dev/null

echo "Done."