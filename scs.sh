#!/bin/sh

# URL of the shell script on GitHub (use raw content URL)
SCRIPT_URL="https://raw.githubusercontent.com/username/repo/branch/script.sh"

# Local path where the script will be downloaded
LOCAL_SCRIPT_PATH="/tmp/downloaded_script.sh"

# Function to download and run the script
download_and_run() {
    # Download the script
    if curl -s -L "$SCRIPT_URL" -o "$LOCAL_SCRIPT_PATH"; then
        echo "Script downloaded successfully"
        
        # Make it executable
        chmod +x "$LOCAL_SCRIPT_PATH"
        
        # Run the script
        sh "$LOCAL_SCRIPT_PATH"
    else
        echo "Failed to download script from $SCRIPT_URL"
    fi
}

# Run immediately
download_and_run

# Then run every 5 minutes
while true; do
    sleep 300  # 300 seconds = 5 minutes
    download_and_run
done
