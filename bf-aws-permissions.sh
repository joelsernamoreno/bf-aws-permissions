#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Show help message
show_help() {
    echo "Usage: $0 -p <profile> -r <region> [-v] [-s <service1|service2>] [-d]"
    echo ""
    echo "Options:"
    echo "  -p PROFILE   AWS CLI profile name (required)"
    echo "  -r REGION    AWS region (required, e.g., us-east-1)"
    echo "  -s SERVICES  Pipe-separated services to enumerate (e.g., 'lambda|s3|ec2')"
    echo "  -v           Verbose mode (shows more output)"
    echo "  -d           Debug mode (shows internal variables)"
    echo "  -h           Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 -p EC2Role4Scenario -r us-east-1 -s 'lambda'"
    echo "  $0 -p EC2Role4Scenario -r us-east-1 -s 's3|ec2|lambda|iam' -v"
    echo "  $0 -p EC2Role4Scenario -r us-east-1  # Enumerate ALL services"
    exit 0
}

# Default values
VERBOSE=""
DEBUG=""
SERVICES=""

# Parse command line arguments
while getopts "p:r:s:vdh" opt; do
    case $opt in
        p) PROFILE="$OPTARG" ;;
        r) REGION="$OPTARG" ;;
        s) SERVICES="$OPTARG" ;;
        v) VERBOSE="--verbose" ;;
        d) DEBUG="--debug" ;;
        h) show_help ;;
        *) show_help ;;
    esac
done

# Validate required arguments
if [ -z "$PROFILE" ] || [ -z "$REGION" ]; then
    echo -e "${RED}Error: Profile and Region are required${NC}"
    show_help
fi

# Convert pipe-separated services to Python list format
if [ ! -z "$SERVICES" ]; then
    # Replace | with , for the Python list
    SERVICES_LIST=$(echo $SERVICES | tr '|' ',')
    
    # Build Python list: ["s3","ec2","lambda"]
    PY_SERVICES="["
    IFS=',' read -ra ADDR <<< "$SERVICES_LIST"
    for i in "${ADDR[@]}"; do
        # Trim whitespace and add quotes
        trimmed=$(echo $i | xargs)
        PY_SERVICES="${PY_SERVICES}\"$trimmed\","
    done
    PY_SERVICES="${PY_SERVICES%,}]"  # Remove trailing comma and close bracket
else
    PY_SERVICES="[]"  # Empty list means enumerate ALL services
fi

# Debug mode: show internal variables
if [ ! -z "$DEBUG" ]; then
    echo -e "${YELLOW}[DEBUG] Debug Mode ON${NC}"
    echo -e "${YELLOW}[DEBUG] Profile: $PROFILE${NC}"
    echo -e "${YELLOW}[DEBUG] Region: $REGION${NC}"
    echo -e "${YELLOW}[DEBUG] Raw services: $SERVICES${NC}"
    echo -e "${YELLOW}[DEBUG] Services list: $SERVICES_LIST${NC}"
    echo -e "${YELLOW}[DEBUG] Python services: $PY_SERVICES${NC}"
fi

# Verbose mode: show start message
if [ ! -z "$VERBOSE" ]; then
    echo -e "${GREEN}[*] Starting permission enumeration with profile: $PROFILE in region: $REGION${NC}"
else
    echo -e "${GREEN}[*] Enumerating permissions...${NC}"
fi

# Execute the Python script
python3 -c "
from aws_bruteforce import AWSBruteForce
from colorama import init
import sys

# Initialize colorama for cross-platform colored output
init(autoreset=True)

try:
    # Create AWSBruteForce instance with the provided parameters
    bf = AWSBruteForce(
        debug=${DEBUG:-False},
        region='$REGION',
        profile='$PROFILE',
        aws_services=$PY_SERVICES,
        threads=10,
        access_key_id=None,
        secret_access_key=None,
        session_token=None
    )
    
    # Run the brute force enumeration
    found = bf.brute_force_permissions()
    
    # Display results
    print(f'\n${GREEN}Permissions found:${NC}')
    if found:
        for perm in sorted(found):
            print(f'  - {perm}')
    else:
        print(f'  ${YELLOW}No permissions found or all access denied${NC}')
        
except Exception as e:
    print(f'${RED}Error: {e}${NC}')
    sys.exit(1)
"

# Check exit status
if [ $? -eq 0 ]; then
    echo -e "${GREEN}Permission enumeration completed successfully${NC}"
else
    echo -e "${RED}Permission enumeration failed${NC}"
    exit 1
fi
