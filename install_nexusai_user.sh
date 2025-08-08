#!/bin/bash

# NexusAI User-Level Installation Script
# This script installs NexusAI for the current user

set -e

echo "🔧 Installing NexusAI for current user..."

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$SCRIPT_DIR"

# Create user's bin directory if it doesn't exist
USER_BIN="$HOME/bin"
mkdir -p "$USER_BIN"

# Create the user-level wrapper script
USER_SCRIPT="$USER_BIN/nexusai"

echo "📁 Creating user-level wrapper script..."

# Create the wrapper script
cat > "$USER_SCRIPT" << 'EOF'
#!/bin/bash

# NexusAI - AI-Powered Network Security Analysis Tool
# User-level wrapper script

# Get the directory where the original script is located
SCRIPT_DIR="$PROJECT_DIR"

# Check if the project directory exists
if [ ! -d "$SCRIPT_DIR" ]; then
    echo "❌ Error: NexusAI project directory not found at $SCRIPT_DIR"
    echo "Please ensure the project is installed correctly."
    exit 1
fi

# Change to the project directory
cd "$SCRIPT_DIR"

# Check if virtual environment exists
if [ -d "venv" ]; then
    # Activate virtual environment and run NexusAI
    source venv/bin/activate
    python -m nexus.cli.commands "$@"
else
    # Try to run directly if no virtual environment
    python -m nexus.cli.commands "$@"
fi
EOF

# Make the script executable
chmod +x "$USER_SCRIPT"

# Add to PATH if not already there
if [[ ":$PATH:" != *":$USER_BIN:"* ]]; then
    echo "export PATH=\"\$HOME/bin:\$PATH\"" >> ~/.zshrc
    echo "✅ Added ~/bin to PATH in ~/.zshrc"
fi

echo "✅ NexusAI has been installed for current user!"
echo ""
echo "🎉 You can now use 'nexusai' from anywhere:"
echo "   nexusai --help"
echo "   nexusai --input scan.xml"
echo "   nexusai --check-ips 8.8.8.8"
echo ""
echo "📝 Note: The tool requires the virtual environment to be set up."
echo "   If you haven't set up the environment yet, run:"
echo "   cd $PROJECT_DIR && python -m venv venv && source venv/bin/activate && pip install -e ."
echo ""
echo "🔄 Please restart your terminal or run 'source ~/.zshrc' to use the command immediately." 