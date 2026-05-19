#!/bin/bash
# ShieldWatch/ZynChat Installation Script
# Handles native module compilation (bcrypt) and dependency resolution

echo "🚀 Starting installation..."

# Ensure we are in the project root
cd "$(dirname "$0")/.."

# Check Node.js version
NODE_VER=$(node -v)
echo "📦 Node.js version: $NODE_VER"

# Clean old artifacts
rm -rf node_modules package-lock.json

# Install dependencies with legacy peer deps and source build for bcrypt
echo "📥 Installing dependencies (this may take a while to compile bcrypt)..."
npm install --legacy-peer-deps --build-from-source

if [ $? -eq 0 ]; then
  echo "✅ Installation complete!"
else
  echo "❌ Installation failed. Checking for build tools..."
  # Suggest build tools if failure
  if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    echo "💡 Try running: sudo apt-get install build-essential python3"
  fi
  exit 1
fi
