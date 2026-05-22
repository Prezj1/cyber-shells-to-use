#!/bin/bash

# Check if an input file was provided
if [ -z "$1" ]; then
    echo "[-] Usage: $0 <nmap_output_file.txt>"
    exit 1
fi

NMAP_FILE="$1"

# Verify the file exists
if [ ! -f "$NMAP_FILE" ]; then
    echo "[-] Error: File '$NMAP_FILE' not found."
    exit 1
fi

echo "[+] Parsing $NMAP_FILE for service versions..."
echo "=================================================="

# Read the file line by line looking for open ports
# This regex extracts lines containing 'open', then grabs the service name and version
grep "open" "$NMAP_FILE" | while read -r line; do
    
    # Extract port/protocol (e.g., 80/tcp)
    PORT=$(echo "$line" | awk '{print $1}')
    
    # Extract the service name and version details
    # This cuts out the port status and joins the rest of the line
    SERVICE_INFO=$(echo "$line" | awk '{$1=$2=""; print $0}' | sed 's/^[ \t]*//')
    
    # If the service info is empty, skip it
    if [ -z "$SERVICE_INFO" ] || [ "$SERVICE_INFO" == "unrecognized" ]; then
        continue
    fi

    echo ""
    echo "[*] Port $PORT: Checking Searchsploit for: $SERVICE_INFO"
    echo "--------------------------------------------------"
    
    # Run searchsploit against the extracted string
    searchsploit "$SERVICE_INFO"
    
    # Optional: If searchsploit returns nothing, try a broader search using just the first two words
    # (e.g., "Apache httpd 2.4.41" becomes "Apache httpd")
    if [ $? -eq 0 ]; then
        BROAD_SEARCH=$(echo "$SERVICE_INFO" | awk '{print $1, $2}')
        # Check if the broad search is different from the original to avoid duplicate output
        if [ "$BROAD_SEARCH" != "$SERVICE_INFO" ]; then
            echo "[i] No direct version match? Try broad search: searchsploit \"$BROAD_SEARCH\""
        fi
    fi
    echo "--------------------------------------------------"
done