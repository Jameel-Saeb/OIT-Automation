#!/bin/bash
# Cleanup script to kill any lingering Chrome/ChromeDriver processes

echo "Cleaning up Chrome and ChromeDriver processes..."

# Kill ChromeDriver processes
pkill -9 chromedriver 2>/dev/null && echo "✓ Killed ChromeDriver processes" || echo "No ChromeDriver processes found"

# Kill Chrome processes started by automation (they have --remote-debugging-port)
ps aux | grep -i "chrome.*remote-debugging-port" | grep -v grep | awk '{print $2}' | xargs kill -9 2>/dev/null && echo "✓ Killed automation Chrome processes" || echo "No automation Chrome processes found"

echo "Cleanup complete!"
