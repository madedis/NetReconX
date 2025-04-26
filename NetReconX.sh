#!/usr/bin/env bash

# Color and effect setup using tput for better portability
setup_colors() {
    if [[ -t 2 ]]; then
        RED=$(tput setaf 1)
        GREEN=$(tput setaf 2)
        YELLOW=$(tput setaf 3)
        BLUE=$(tput setaf 4)
        CYAN=$(tput setaf 6)
        NC=$(tput sgr0)          # No Color
        BOLD=$(tput bold)
        BLINK=$(tput blink)
    else
        RED='' GREEN='' YELLOW='' BLUE='' CYAN='' NC='' BOLD='' BLINK=''
    fi
}

# Function to center text
center_text() {
    local cols=$(tput cols)
    local text_length=${#1}
    local half_input_length=$(( $text_length / 2 ))
    local half_col=$(( $cols / 2 ))
    local start_point=$(( $half_col - $half_input_length ))
    printf "%${start_point}s" ''
    printf "%s\n" "$1"
}

# Function to display animated banner
show_banner() {
    local banner=(
        " _   _      _   ____                       __  __"
        "| \ | | ___| |_|  _ \ ___  ___ ___  _ __  \ \/ /"
        "|  \| |/ _ \ __| |_) / _ \/ __/ _ \| '_ \  \  / "
        "| |\  |  __/ |_|  _ <  __/ (_| (_) | | | | /  \ "
        "|_| \_|\___|\__|_| \_\___|\___\___/|_| |_|/_/\_\\"
    )
    
    echo -e "${BLUE}${BOLD}"
    for line in "${banner[@]}"; do
        center_text "$line"
        sleep 0.1
    done
    echo -e "${NC}"
}

# Function to show spinner
spinner() {
    local pid=$!
    local delay=0.15
    local spinstr='|/-\'
    while [ "$(ps a | awk '{print $1}' | grep $pid)" ]; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    printf "    \b\b\b\b"
}

# Main script
setup_colors
clear

# Display animated banner
show_banner

# Initial message with border
echo -e "${CYAN}${BOLD}$(center_text "[*] Created by : made.dis")${NC}"
sleep 0.8

# Simulated scan progress with spinner and messages
(
echo -e "\n${YELLOW}Initializing scan parameters...${NC}"
sleep 1
echo -e "${YELLOW}Scanning local subnet...${NC}"
sleep 1
echo -e "${YELLOW}Identifying connected devices...${NC}"
sleep 1
echo -e "${YELLOW}Analyzing network traffic...${NC}"
sleep 1
) & spinner

#  blinking effect
echo -e "\n\n${GREEN}${BOLD}$(center_text "[+] Scanning Started  !")${NC}"
echo -e "${BLINK}${GREEN}$(center_text "-----------")${NC}${NC}"
echo -e "${BOLD}${CYAN}$(printf '%*s' $(tput cols) | tr ' ' '=')${NC}"
# Framework to execute all steps
#♣ Configuration: Parameterize key logic for flexibility
CONFIG_FILE="config.cfg"
DEBUG_MODE=true  # Set to false to disable debug logs
OUTPUT_DIR="./output_dir"
#♣ Ensure output directory exists
mkdir -p "$OUTPUT_DIR" 


LOG_FILE="netreconx.log"




#♣ Load configuration file
if [[ -f "$CONFIG_FILE" ]]; then
    source "$CONFIG_FILE"
else
    echo "ERROR: Configuration file '$CONFIG_FILE' not found."
    exit 1
fi

#♣ Ensure output directory exists
mkdir -p "$OUTPUT_DIR" 

# Logging function
log() {
    local message="$1"
    local level="${2:-INFO}"
    echo "$(date +"%Y-%m-%d %H:%M:%S") - $level - $message" >> "$LOG_FILE"
    if [[ "$DEBUG_MODE" == true && "$level" == "DEBUG" ]]; then
        echo "DEBUG: $message"
    fi
}

   # Stores validated variables
declare -gA url_array
declare -gA field_attributes
 declare -gA input_fields




# Associative arrays for Nmap options



declare -gA HOST_DISCOVERY_OPTIONS

declare -gA SCAN_TECHNIQUES_OPTIONS

declare -gA PORT_SPECIFICATION_OPTIONS

declare -gA SERVICE_VERSION_DETECTION_OPTIONS

declare -gA SCRIPT_SCAN_OPTIONS

declare -gA OS_DETECTION_OPTIONS

declare -gA FIREWALL_IDS_EVASION_OPTIONS

declare -gA OUTPUT_OPTIONS

declare -gA TIMING_PERFORMANCE_OPTIONS

declare -gA AGGRESSIVE_SCAN_OPTIONS

declare -gA NDFIFF_COMPARISON_OPTIONS

declare -gA STAGE_0

declare -gA STAGE_1



# Declare an associative array to store file paths for Nmap output

declare -gA tooler_output_files



# Populate the HOST_DISCOVERY_OPTIONS



HOST_DISCOVERY_OPTIONS=(

  ["List_Scan"]="-sL"

  ["Treat_All_Hosts_As_Online"]="-Pn"

  ["TCP_SYN_Discovery"]="-PS"

  ["UDP_Discovery"]="-PU"

  ["SCTP_Discovery"]="-PY"

  ["System_DNS"]="--system-dns"

  ["Traceroute"]="--traceroute"

)



# Populate the SCAN_TECHNIQUES_OPTIONS



SCAN_TECHNIQUES_OPTIONS=(

  ["TCP_SYN_Scan"]="-sS"

  ["TCP_Connect_Scan"]="-sT"

  ["TCP_ACK_Scan"]="-sA"

  ["TCP_Window_Scan"]="-sW"

  ["TCP_Maimon_Scan"]="-sM"

  ["UDP_Scan"]="-sU"

  ["TCP_Null_Scan"]="-sN"

  ["TCP_FIN_Scan"]="-sF"

  ["TCP_Xmas_Scan"]="-sX"



)



# populate the PORT_SPECIFICATION_OPTIONS



 PORT_SPECIFICATION_OPTIONS=(

  ["thsd_PORT_RANGES"]="-p 21-81" # JUST FOR TESTING 

  ["FAST_MODE"]="-F"

  ["OPEN_PORTS"]="--open" 

  ["UNASSIGNED_ASSIGNED_PORTS"]="-p-"



)



# populate the SERVICE_VERSION_DETECTION_options



 SERVICE_VERSION_DETECTION_OPTIONS=(

   ["DETAILED_VERSION_SCAN"]="--version-trace"

   ["VERSION_DETECTION"]="-sV"               

   ["INTENSITY_LIGHT"]="--version-intensity 2" 

   ["INTENSITY_MEDIUM"]="--version-intensity 5" 

   ["INTENSITY_AGGRESSIVE"]="--version-intensity 9" 

   ["SERVICE_PROBES"]="--version-all"       

   ["SERVICE_NULL"]="--version-light"       

) 



# populate the SCRIPT_SCAN_OPTIONS



 SCRIPT_SCAN_OPTIONS=(

  ["DEFAULT_SCRIPT"]="-sC"

  ["SHOW_DATA_SENT_RECEIVED"]="--script-trace"

  ["UPDATE_SCRIPT_DATABASE"]="--script-updatedb"



) 



# Populate the OS_DETECTION_OPTIONS array



OS_DETECTION_OPTIONS=(



  ["Enable_OS_Detection"]="-O"

  ["Limit_OS_Detection"]="--osscan-limit"

  ["Aggressive_OS_Guess"]="--osscan-guess"



)





# Populate the MISC_OPTIONS array 



MISC_OPTIONS=(



 ["Enable_IPv6_Scanning"]="-6"

 ["Aggressive_Scan"]="-A"

 ["Send_Raw_Ethernet_Frames"]="--send-eth"

 ["Send_Raw_IP_Packets"]="--send-ip"

 ["Assume_Privileged_User"]="--privileged"

 ["Assume_Unprivileged_User"]="--unprivileged"

 ["Print_Version"]="-V"

 ["Print_Help"]="-h"



)



# Populate the FIREWALL_IDS_EVASION_OPTIONS array 



FIREWALL_IDS_EVASION_OPTIONS=(



  ["Fragment_Packets"]="-f"

  ["Fragment_Packets_With_MTU"]="--mtu"

  ["Use_Decoys"]="-D"

  ["Spoof_Source_Address"]="-S"

  ["Use_Specified_Interface"]="-e"

  ["Use_Given_Port_Number"]="-g/--source-port"

  ["Append_Random_Data"]="--data-length"

  ["Send_With_IP_Options"]="--ip-options"

  ["Set_TTL"]="--ttl"

  ["Spoof_MAC_Address"]="--spoof-mac"

  ["Send_Bad_Checksum_Packets"]="--badsum"

)





# Populate the OUTPUT_OPTIONS array

#OUTPUT_OPTIONS=(

 #["Output_Normal_Format"]="-oA"

 #["Output_XML_Format"]="-oX"

 #["Output_Script_Kiddie_Format"]="-oS"

 #["Output_Grepable_Format"]="-oG"

 #["Log_Errors"]="--log-errors"

 #["Append_Output"]="--append-output"

#)



# Populate the TIMING_PERFORMANCE_OPTIONS array

TIMING_PERFORMANCE_OPTIONS=(



  ["Insane_Timing_Template"]="-T5"

  ["Aggressive_Timing_Template"]="-T4"

  ["Normal_Timing_Template"]="-T3"

  ["Polite_Timing_Template"]="-T2"

  ["Sneaky_Timing_Template"]="-T1"

  ["Paranoid_Timing_Template"]="-T0"

  ["Host_Timeout"]="--host-timeout"

  ["Scan100_Delay"]="--scan-delay 100ms"

  ["Max500_Scan_Delay"]="--max-scan-delay 500ms"

  ["Min100_Packet_Rate"]="--min-rate 100"

  ["Max500_Packet_Rate"]="--max-rate 500"



)



#populate AGGRESSIVE_SCAN_OPTIONS



 AGGRESSIVE_SCAN_OPTIONS=(

  ["Aggressive_Scan"]="-A"

  ["Additional_Aggressive"]="--unprivileged"



)



#populate  NDFIFF_COMPARISON_OPTIONS



  NDFIFF_COMPARISON_OPTIONS=(

 ["Ndiff_Comparison"]="--ndiff"

 ["Comparison_Output"]="--output"



)



# Define stages of scanning + remove the simple array declaration with an associative array declare -gA 

# the format should be ["options"]="${!HOST_DISCOVERY_OPTIONS[UDP_DISCOVERY]}"



STAGE_0=( 



   #["Host_D1"]="${HOST_DISCOVERY_OPTIONS[UDP_Discovery]}"

   #["Host_D2"]="${HOST_DISCOVERY_OPTIONS[TCP_SYN_Discovery]}"

    #["Scan_Tech1"]="${SCAN_TECHNIQUES_OPTIONS[UDP_Scan]}"

    ["Scan_Tech2"]="${SCAN_TECHNIQUES_OPTIONS[TCP_SYN_Scan]}"

   #["Port_Spec"]="${PORT_SPECIFICATION_OPTIONS[UNASSIGNED_ASSIGNED_PORTS]}"

    ["OpenP"]="${PORT_SPECIFICATION_OPTIONS[OPEN_PORTS]}"

   #["Timing_Perf"]="${TIMING_PERFORMANCE_OPTIONS[Insane_Timing_Template]}"

    

)



STAGE_1=(   



    ["arg1"]="${SERVICE_VERSION_DETECTION_OPTIONS[DETAILED_VERSION_SCAN]}"

    #["arg2"]="${OS_DETECTION_OPTIONS[Aggressive_OS_Guess]}" 

    #["arg3"]="${SCAN_TECHNIQUES_OPTIONS[UDP_Scan]}" 

    ["arg3"]="${SCAN_TECHNIQUES_OPTIONS[TCP_SYN_Scan]}" 

    #["arg4"]="${PORT_SPECIFICATION_OPTIONS[UNASSIGNED_ASSIGNED_PORTS]}"

    ["arg5"]="${SCRIPT_SCAN_OPTIONS[DEFAULT_SCRIPT]}"

    ["arg6"]="${TIMING_PERFORMANCE_OPTIONS[Normal_Timing_Template]}"

    ["arg7"]="${SERVICE_VERSION_DETECTION_OPTIONS[VERSION_DETECTION]}"

)



#STAGE_2=(
#     ["arg1"]="${SOME_OPTION}"
#     ["arg2"]="${ANOTHER_OPTION}"
#)



# Tooler function: running a Network Mapper 

tooler() {



    local stage=$1

    local target=$2

    local scan_options=""

    local timestamp=$(date +"%Y%m%d_%H%M%S")

    local output_file="results_${timestamp}"

    local error_file="errors_${timestamp}.log"

    local log_file="log_${timestamp}.log"



#Directory checker lare 



  # Validate input

  

  if [[ -z "$stage" || -z "$target" ]]; then

    echo "Error: Stage and target must be provided."

    return 1

  fi



  if [[ ! "$stage" =~ ^[0-3]$ ]]; then

    echo "Error: Invalid stage. Please choose a stage between 0 and 3."

    return 1

  fi



  # Open log file

  

  exec 3> "$log_file"

  



  log "Stage: $stage"

  log "Target: $target"

  

  # Process options based on the stage

  # add iteration through those associative arrays to collect the right argument to addd later !!! not a necessity for my case 

 #replace stages with associative arrays and iterate through them using index 

  case $stage in

    0)

      log "Starting Stage 0 scan."  

      for option_group in "${!STAGE_0[@]}"; do

      option="${STAGE_0[$option_group]}"  # Get the value for this option_group

          log "Processing option group: $option_group with value: $option"

          scan_options+="$option "

          log "Adding option: $option"

      done

      ;;

    1)

      log "Starting Stage 1 scan."

for option_group in "${!STAGE_1[@]}"; do

  option="${STAGE_1[$option_group]}"  # Get the value for this option_group

  log "Processing option group: $option_group with value: $option"

  scan_options+="$option "

  log "Adding option: $option"

done

      ;;

    2)

     for option_group in "${!STAGE_2[@]}"; do

  option="${STAGE_2[$option_group]}"  # Get the value for this option_group

  log "Processing option group: $option_group with value: $option"

  scan_options+="$option "

  log "Adding option: $option"

done
      ;;

    3)

      log "Starting Stage 3 scan."

      for option_group in "${!STAGE_3[@]}"; do

      option="${STAGE_3[$option_group]}"  # Get the value for this option_group

          log "Processing option group: $option_group with value: $option"

          scan_options+="$option "

          log "Adding option: $option"

      done

      ;;

    *)

      echo "Invalid stage. Please choose a stage between 0 and 3 .For the moment working on the other ones "

      log "Error: Invalid stage $stage provided. Please check the error file."

      return 1

      ;;

  esac



  

  log "Scan Options: $scan_options"



  # Log the Nmap command

  

  log "Running Nmap with options: $scan_options on target: $target"

  

  # Run Nmap with the selected options

  

  nmap $scan_options "$target" -oA "$output_file" 2> "$error_file"



  # Check if Nmap execution was successful

  

  if [[ $? -ne 0 ]]; then

    log "Error: Nmap scan failed. Check the error log at $error_file."

    return 1

  fi



  log "Scan completed. Results saved to $output_file."

  

  # push the output file to be the input file of the function file cleaner as argument $3 and cleaned file is $4.

   

    # Store the generated file paths in the associative array

    tooler_output_files["gnmap"]="${output_file}.gnmap"

    tooler_output_files["xml"]="${output_file}.xml"

    tooler_output_files["nmap"]="${output_file}.nmap"
     
    tooler_output_files["json"]="${output_file}.json"



    echo "Scan completed. Files stored:" >> "$log_file"

    for format in "${!tooler_output_files[@]}"; do

        echo "$format: ${tooler_output_files[$format]}" >> "$log_file"

    done



}


# Call the tooler function with arguments
Investigator() {
    echo "🔍 Injection Testing Script - Start of Task: Created by Mocro_0rc1nus"
    echo "-------------------------------------------"

    local XML_FILE="./${tooler_output_files["xml"]}"
    if [[ ! -f "$XML_FILE" ]]; then
        echo "❌ Error: XML file '$XML_FILE' not found."
        return 1
    fi

    # Extract IP and FQDN
    ip_address=$(xmllint --xpath 'string(//address/@addr)' "$XML_FILE" 2>/dev/null)
    fqdn=$(xmllint --xpath 'string(//hostname/@name)' "$XML_FILE" 2>/dev/null)
    if [[ -z "$ip_address" || -z "$fqdn" ]]; then
        echo "❌ Error: Failed to extract IP address or hostname from XML file."
        return 1
    fi
    echo "✅ Extracted IP Address: $ip_address"
    echo "✅ Extracted Hostname: $fqdn"

    # Extract URLs from XML
    declare -gA RAW_LINKS_XML
    RAW_LINKS_XML=(
        [raw_urls]="$(xmllint --xpath '//script/@output' "$XML_FILE" 2>/dev/null)"
        [extra_urls]="$(xmllint --xpath '//elem/text()' "$XML_FILE" 2>/dev/null)"
        [ip_urls]="$(xmllint --xpath '//table/@key' "$XML_FILE" 2>/dev/null)"
        [main_url]="$fqdn"
    )

    # Clean IP-based URLs
    cleaned_ip_urls=$(echo "${RAW_LINKS_XML[ip_urls]}" | tr -d '"' | tr -s '\n' ' ')

    # Combine FQDN and IP-based URLs
    valid_ip_urls=$(echo -e "$fqdn" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}(:[0-9]+)?(/[^ ]*)?|'"$fqdn" | sort -u)

    if [[ -z "$valid_ip_urls" ]]; then
        echo "❌ Error: No valid URLs found."
        return 1
    else
        echo "✅ Extracted START FROM Address URLs:"
        echo "$valid_ip_urls"
        all_urls=$(echo "$valid_ip_urls" | sort -u)
    fi

    # Combine and deduplicate URLs
    declare -gA url_array
    index=0
    while IFS= read -r url; do
        url_array[$index]="$url"
        index=$((index+1))
    done <<< "$all_urls"

    # Update /etc/hosts if necessary
    if ! grep -q "$fqdn" /etc/hosts; then
        echo "📝 Adding $fqdn to /etc/hosts"
        echo "$ip_address $fqdn" | sudo tee -a /etc/hosts >/dev/null || {
            echo "❌ Error: Failed to update /etc/hosts."
            return 1
        }
    else
        echo "ℹ️ $fqdn already exists in /etc/hosts"
    fi

    # Function to clean and fetch URLs
    fetch_and_dump_html() {
        local url=$1

        # Clean single URL
        local clean_url=$(echo "$url" | sed -E 's#([^:])/{2,}#\1/#g')

        # Clean all URLs in valid_ip_urls (line by line)
        local clean_ip_urls=""
        while IFS= read -r line; do
            clean_ip_urls+=$(echo "$line" | sed -E 's#([^:])/{2,}#\1/#g')$'\n'
        done <<< "$valid_ip_urls"

        echo "Cleaned URL: $clean_url"
        echo "Cleaned IP URLs: $clean_ip_urls"

        # Ensure the output directory exists
        mkdir -p "dumped_html"

        # File names for primary and IP URLs
        local file_name_primary=$(echo "$clean_url" | sed 's/[^a-zA-Z0-9]/_/g').html
        local file_name_ip=$(echo "$clean_ip_urls" | sed 's/[^a-zA-Z0-9]/_/g').html

        echo "🌐 Dumping HTML from: http://$clean_url"
        if ! curl -s "http://$clean_url" -o "dumped_html/$file_name_primary"; then
            echo "🔴 Failed to fetch primary URL: http://$clean_url"
            return 1
        fi

        echo "🌐 Dumping HTML from: http://$clean_ip_urls"
        if ! curl -s "http://$clean_ip_urls" -o "dumped_html/$file_name_ip"; then
            echo "🔴 Failed to fetch IP URL: http://$clean_ip_urls"
            return 1
        fi

        # Process links from primary URL
        process_links "dumped_html/$file_name_primary" "$clean_url"

        # Process links from IP URL if no new links were found from the primary URL
        if [[ ${#url_array[@]} -eq 0 ]]; then
            echo "No new links found from primary URL. Processing global IP URL."
            process_links "dumped_html/$file_name_ip" "$clean_ip_urls"
        fi
    }

    # Function to process links
    process_links() {
        local file=$1
        local base_url=$2
        local new_links_found=0  # Flag to track if new links are found

        # Declare global associative arrays
        declare -gA seen_urls
        declare -gA subdoms_found  # Stores unique subdomains found

        # Use grep to find all potential subdomains in the file
        grep -oE '([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})' "$file" | sort -u | while read -r subdomain; do
            # Avoid processing subdomains we already found
            if [[ -z "${subdoms_found[$subdomain]}" ]]; then
                subdoms_found["$subdomain"]=1
                echo "🌍 Found new subdomain: $subdomain"

                # Now find all links (href/src) from the file
                grep -oE 'href="([^"]+)"|src="([^"]+)"|value="([^"]+)"|action="([^"]+)"' "$file" | cut -d'"' -f2 | while read -r link; do
                    # Ignore unwanted links
                    [[ "$link" == *#* || "$link" == */static/* || "$link" == *.css ]] && continue

                    clean_link=$(echo "$link" | sed -E 's#^/##' | sed -E 's#([^:])/{2,}#\1/#g')
                    if [[ -z "$clean_link" ]]; then
                        echo "🔴 Empty link. Skipping."
                        continue
                    fi

                    # Convert relative links to absolute if needed
                    if [[ "$clean_link" != http* ]]; then
                        full_url="http://$subdomain/$clean_link"
                    else
                        full_url="$clean_link"
                    fi

                    # Process the full URL if it's new
                    if validate_url "$full_url"; then
                        if [[ -z "${seen_urls[$full_url]}" ]]; then
                            seen_urls["$full_url"]=1
                            url_array+=("$full_url")
                            new_links_found=1  # Set flag to indicate new links were found
                            echo "📌 Found filtered sub-link: $full_url"

                            # Generate file name based on the full URL
                            dump_file=$(echo "$full_url" | sed 's/[^a-zA-Z0-9]/_/g').html
                            if [[ -z "$dump_file" || "$dump_file" == ".html" ]]; then
                                echo "🔴 Invalid file name: $dump_file. Skipping."
                                continue
                            fi

                            # Dump HTML for sub-link
                            if ! curl -sL "$full_url" -o "dumped_html/$dump_file"; then
                                echo "🔴 Failed to fetch sub-link: $full_url"
                            fi
                        else
                            echo "ℹ️ URL already processed: $full_url. Skipping."
                        fi
                    else
                        echo "🔴 Invalid URL: $full_url. Skipping."
                    fi
                done
            fi
        done
    }

    # Initial URL processing
    for url in "${url_array[@]}"; do
        fetch_and_dump_html "$url"
    done

    # Recursively check for new URLs in all dumped HTML files
    while [[ ${#url_array[@]} -gt 0 ]]; do
        current_url=${url_array[0]}
        unset "url_array[0]"  # Remove the first element
        echo "🔍 Recursively checking: $current_url"

        # Process primary URL
        file_name=$(echo "$current_url" | sed 's/[^a-zA-Z0-9]/_/g').html
        echo "🌐 Dumping HTML from: http://$current_url"
        curl -sL "http://$current_url" -o "dumped_html/$file_name" || {
            echo "🔴 Failed to fetch URL: $current_url"
            continue
        }

        # Extract links from the current HTML page
        new_links_found=0  # Flag to track if new links are found
        grep -oE 'href="([^"]+)"|src="([^"]+)|action="([^"]+)""' "dumped_html/$file_name" | cut -d'"' -f2 | while read -r link; do
            # Ignore unwanted links
            [[ "$link" == *#* || "$link" == */static/* || "$link" == *.css ]] && continue

            clean_link=$(echo "$link" | sed -E 's#^/##' | sed -E 's#([^:])/{2,}#\1/#g')

            if [[ "$clean_link" != http* ]]; then
                # If the link is relative, prepend the current URL
                full_url="http://$current_url/$clean_link"
            else
                # If it's already an absolute URL, just use it directly
                full_url="$clean_link"
            fi

            # Extract the domain from the full URL (excluding protocol part)
            domain=$(echo "$full_url" | sed -E 's#^(http[s]?://)([^/]+)#\2#')

           # Check if the base_fqdn exists within the domain
    if [[ "$domain" != *"$fqdn"* ]]; then
        echo "❌ Domain $domain does NOT contain $fqdn — Skipping..."
        continue  # Stop processing this link and move to the next one
    fi

    echo "✔️ Domain $domain contains $fqdn — Proceeding..."

            # Process and store the full URL
            echo "📌 Found filtered sub-link: $full_url"
            url_array+=("$full_url")
            new_links_found=1  # Set flag to indicate new links were found

            # Dump HTML for sub-link
            dump_file=$(echo "$full_url" | sed 's/[^a-zA-Z0-9]/_/g').html
            curl -sL "$full_url" -o "dumped_html/$dump_file" || {
                echo "🔴 Failed to fetch sub-link: $full_url"
            }
        done

        # If no new links were found, stop further processing
        if [[ $new_links_found -eq 0 ]]; then
            echo "ℹ️ No new links found. Stopping recursion."
            break
        fi
    done

    # Duplicate removal based on file size
    declare -gA file_sizes
    for original in dumped_html/*.html; do
        if [[ -f "$original" ]]; then
            size=$(stat -c %s "$original")
            if [[ -n "${file_sizes[$size]}" ]]; then
                echo "Duplicate found: $original (same size as ${file_sizes[$size]}), deleting..."
                rm -f "$original"
            else
                file_sizes[$size]="$original"
            fi
        fi
    done

    # Extract input fields from dumped HTML files
    # Color definitions for terminal output
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    NC='\033[0m' # No Color

    declare -gA input_fields

    # Function to colorize the output based on the type of field
    colorize_field() {
        local field_type=$1
        case $field_type in
            "text"|"password"|"email"|"textarea"|"select")
                echo -e "${GREEN}$field_type${NC}"
                ;;
            "hidden"|"checkbox"|"radio")
                echo -e "${YELLOW}$field_type${NC}"
                ;;
            "submit"|"button"|"image")
                echo -e "${BLUE}$field_type${NC}"
                ;;
            *)
                echo -e "${RED}$field_type${NC}"
                ;;
        esac
    }

    # Check if the directory exists
    if [[ ! -d "dumped_html" ]]; then
        echo -e "${RED}Error: Directory 'dumped_html' does not exist.${NC}"
        exit 1
    fi

    # Analyze all web accessible files
    shopt -s nullglob # Prevent globbing from returning the literal pattern if no files match
    for file in dumped_html/*.{html,php,js,json}; do
        echo -e "🔍 Extracting input fields from ${BLUE}$file${NC}"
        grep -oE '<(input|textarea|select|form|action)[^>]*>' "$file" | while read -r field; do
            field_name=$(echo "$field" | grep -oE 'name="[^"]*"' | cut -d'"' -f2)
            field_type=$(echo "$field" | grep -oE 'type="[^"]*"' | cut -d'"' -f2)
            
            # If no type is found, default to the tag name (e.g., textarea, select)
            if [[ -z "$field_type" ]]; then
                field_type=$(echo "$field" | grep -oE '<(textarea|select|form|input)' | cut -d'<' -f2)
            fi
            
            if [[ -n "$field_name" ]]; then
                input_fields["$field_name"]="$field_type"
                echo -e "Found field: ${YELLOW}$field_name${NC} of type $(colorize_field "$field_type")" 
            fi
            
            # Save the findings to a file
            output_file="interesting_findings.txt"
            echo "Interesting Findings:" > "$output_file"
            if [[ ${#input_fields[@]} -eq 0 ]]; then
                echo -e "From $file ${RED}No input fields found.${NC}" | tee -a "$output_file"
            else
                for field_name in "${!input_fields[@]}"; do
                    echo -e "From : $file Field: ${YELLOW}$field_name${NC}, Type: $(colorize_field "${input_fields[$field_name]}")" >> "$output_file"
                done
                echo -e "${GREEN}Findings saved to $output_file${NC}"
            fi
        done
    done

    

    # Logging function
    log_response() {
        local message="$1"
        echo "$(date '+%Y-%m-%d %H:%M:%S') - $message" >> vulnerability_test.log
    }

    
}
################################################################################################################################################################################################################################################

##########################################################################################################################################################################################################################################

# Associative arrays 



declare -gA SERVICES_FOUND 

declare -gA DEMARCHE

declare -gA USED_OPEN_PORTS

declare -gA DEPLOYED_TOOL_AGENT

declare -gA TEMP_ARRAY_TOOL_TOKEN  





#DEMARCH is a reference Number 1 for Service_Comparaison

     DEMARCHE=(

  ["ftp"]="ftp,ncftp,lftp,hydra,searchsploit"
  ["ssh"]="ssh,hydra,searchsploit"
  ["telnet"]="telnet,nmap,hydra,searchsploit"
  ["smtp"]="smtp-user-enum,swaks,hydra,searchsploit"
  ["dns"]="dig,nslookup,dnsenum,dns_recon,searchsploit"
  ["http"]="sqlmap,sqlcmd,ffuf,gobuster,nikto,wpscan,whatweb,wfuzz,droopescan,joomscan,searchsploit"
  ["pop3"]="pop3brute,searchsploit"
  ["rpcbind"]="rpcinfo,nmap,rpcclient,searchsploit"
  ["imap"]="imapscan,hydra,searchsploit"
  ["imaps"]="imapscan,searchsploit"
  ["pop3s"]="pop3scan,searchsploit"
  ["http-proxy"]="searchsploit"
  ["snmp"]="snmpwalk,snmp-check,searchsploit"
  ["https"]="sslyze,whatweb,ffuf,nikto,gobuster,sqlcmd,sqlmap,wpscan,wfuzz,joomscan,droopescan,searchsploit"
  ["smtps"]="swaks,smtp-user-enum,searchsploit"
  ["syslog"]="syslog-scanner,searchsploit"
  ["postgresql"]="pg_enum,hydra,searchsploit"
  ["vnc"]="vncviewer,vnc-brute,searchsploit"
  ["redis"]="redis-exploit.py,redis-cli,redis-brute,searchsploit"
  ["mongodb"]="mongod_enum,searchsploit"
  ["mysql"]="mysql,mysql-enum,hydra,searchsploit"
  ["rdp"]="rdp-sec-check,xrdp,hydra,searchsploit"
  ["msrpc"]="rpcclient,crackmapexec,searchsploit"
  ["netbios"]="nbtscan,enum4linux,searchsploit"
  ["winrm"]="evil-winrm,crackmapexec,searchsploit"
  ["rstp"]="rstp-scan,searchsploit"
  ["smb"]="smbmap,smbclient,enum4linux,crackmapexec,searchsploit"
  ["x11"]="x11-brute,xeyes,xclock,searchsploit"
  ["flask"]="flask-scan,searchsploit"
  ["dhcp"]="dhcping,dnsmasq,searchsploit"
  ["rip"]="ripv2-scanner,searchsploit"
  ["rexec"]="rexec-scanner,searchsploit"
  ["rlogin"]="rlogin-scanner,searchsploit"
  ["sip"]="sipvicious,sip-scan,searchsploit"
  ["isakmp"]="ike-scan,searchsploit"
  ["kpasswd"]="kinit,kerbrute,searchsploit"
  ["ldap"]="ldapsearch,ldapbrute,crackmapexec,searchsploit"
  ["pop2"]="pop2scan,searchsploit"
  ["imap"]="imapscan,hydra,searchsploit" 

        )









#on the DEPLOYED_TOOL_AGENT where we find the tool which will perform different tasks like the Discovery , Enumeration , Brute-Force...



    declare -gA DEPLOYED_TOOL_AGENT=( 

    ["sslyze"]="SS001"

    ["joomscan"]="JO002"

    ["wpscan"]="WP003"

    ["droopescan"]="DR004"

    ["snmp-check"]="SN005"

    ["smbmap"]="SM006"

    ["enum4linux"]="EN007"

    ["impacket"]="IM008"

    ["redis-exploit.py"]="RE009"

    ["wfuzz"]="WF010"

    ["ffuf"]="FF011"

    ["gobuster"]="GO012"

    ["odat.py"]="OD013"

    ["nmap"]="NM014"

    ["hydra"]="HY015"

    ["medusa"]="ME016"

    ["johntheripper"]="JH017"

    ["smtp_user_enum"]="SM018"

    ["nikto"]="NI019"

    ["mysql-enum"]="MY020"

    ["mysql"]="MY021"

    ["pg_enum"]="PG022"

    ["rdp-sec-check"]="RD023"

    ["xrdp"]="XR024"

    ["redis-brute"]="RE025"

    ["vncviewer"]="VN026"

    ["flask-scan"]="FL027"

    ["xeyes"]="XE028"

    ["xclock"]="XC029"

    ["x11-brute"]="X1030"

    ["sqlmap"]="SQ031"

    ["dig"]="DI032"

    ["vhost"]="VH033"

    ["whatweb"]="WH034"

    ["searchsploit"]="SE035"

    ["rpcclient"]="RP036"

    ["evil-winrm"]="EV037"

    ["redis-cli"]="RE038"

    ["mssql-scriptor"]="MS039"

    ["sqlcmd"]="SQ040"

    ["dns_recon"]="DN041"

    ["nslookup"]="NS042"

    ["kerbrute"]="KE043"

    ["impacket"]="IM044"

    ["kinit"]="KI045"

    ["ldapbrute"]="LD046"

    ["ldapsearch"]="LD047"

    ["crackmapexec"]="CR048"

    ["smb-enum-shares"]="SM049"

    ["smbclient"]="SM050"

    ["ftp"]="FT051"

    ["ssh"]="SS052"

    ["nc"]="NC053"

    ["python3"]="PY054"

    ["telnet"]="TE055"

    ["ncftp"]="NC056"

    ["lftp"]="LF057"

    ["metasploit"]="ME058"

    ["bloodhound"]="BL059"

    ["ligolo-ng"]="LI060"

    ["nbtscan"]="NB061"

    ["imapscan"]="IM062"

    ["pop3scan"]="PO063"

    ["syslog-scanner"]="SY064"

    ["mongod-enum"]="MO065"

    ["dhcping"]="DH066"

    ["dnsmasq"]="DN067"

    ["ripv2-scanner"]="RI068"

    ["rpcinfo"]="RP069"

)







# Ensure it's an associative array



# Ensure it's an associative array
for service in "${!USED_OPEN_PORTS[@]}"; do
    tools="${USED_OPEN_PORTS[$service]}"

    # Split tools into an array using ',' as a delimiter (removing extra spaces)
    IFS=',' read -ra tool_array <<< "$tools"

    # Debugging: Display service and associated tools
    echo -e "\n[INFO] Processing Service: $service"
    echo "  Tools: $tools"

    for tool in "${tool_array[@]}"; do
        # Trim leading/trailing spaces
        tool=$(echo "$tool" | xargs)

        # Debugging: Show the current tool being processed
        echo "  - Tool: $tool"

        # Retrieve the corresponding token from DEPLOYED_TOOL_AGENT
        token="${DEPLOYED_TOOL_AGENT[$tool]}"

        # Debugging: Show the tool-token mapping
        echo "    Token: ${token:-None}"

        # Check if token exists
        if [[ -z "$token" ]]; then
            echo "[WARNING] Tool '$tool' for service '$service' not found in DEPLOYED_TOOL_AGENT."
        else
            # Store token as key and tool as value in TEMP_ARRAY_TOOL_TOKEN
            TEMP_ARRAY_TOOL_TOKEN["$token"]="$tool"
            echo "[UPDATED] TEMP_ARRAY_TOOL_TOKEN: $token -> $tool"
        fi
    done
done
#


#
# -------------------------
# Secondary Function: FILE_CLEANER
# -------------------------
file_cleaner() {
    local input_file="${tooler_output_files["gnmap"]}"
    local cleaned_file="cleaned_${input_file}"

    # Clean file: remove comments, empty lines, and 'Host:' lines
    if ! awk '/Ports:/ {flag=1} flag {gsub(/,/, "\n"); print}' "$input_file" > "$cleaned_file"; then
        echo "[ERROR] Failed to clean file: $input_file"
        return
   fi

    echo "$cleaned_file"
}

# -------------------------
# File Processor Function
# -------------------------
file_processor() {
    local cleaned_file="$1"

    if [[ ! -f "$cleaned_file" ]]; then
        echo "[ERROR] Input file '$cleaned_file' does not exist."
        return
    fi

    while IFS= read -r line; do
        # Skip empty lines or comment lines
        [[ -z "$line" || "$line" =~ ^# ]] && continue

    # Extract details using awk
        port_number=$(echo "$line" | awk -F'Ports: ' '{print $2}' | awk -F'/' '{print $1}')

# Step 2: Check if port_number is valid (between 1 and 65535)
if [[ "$port_number" -ge 1 && "$port_number" -le 65535 ]]; then
    echo "Port Number: $port_number (Valid)"
else
    # Step 3: If not valid, extract from the first field (fallback)
    port_number=$(echo "$line" | awk -F'/' '{print $1}')
    echo "Fallback Port Number: $port_number"
fi
        state=$(echo "$line" | awk -F'/' '{print $2}' | awk '{print $1}')
        service_name=$(echo "$line" | awk -F'//|/' '{print $4}')
        version=$(echo "$line" | awk -F'//|/' '{print $5}')
        additional_text=$(echo "$line" | awk -F'//|/' '{print $4}')

        # Debugging: Display extracted information
        echo -e "\n[INFO] Extracted Details:"
        echo "  Port Number   : $port_number"
        echo "  State         : $state"
        echo "  Service Name  : $service_name"
        echo "  Version       : $version"
        echo "  Additional    : $additional_text"


        SERVICES_FOUND["$port_number"]="$service_name"
        local tools="${DEMARCHE[$service_name]}"

        # Split tools into an array
        IFS=',' read -ra tool_array <<< "$tools"

        # Iterate through tools
        for tool in "${tool_array[@]}"; do
            # Retrieve tokens
            tokens="${DEPLOYED_TOOL_AGENT[$tool]}"

            # Ensure tokens exist before processing
            if [[ -n "$tokens" ]]; then
                IFS=',' read -ra token_array <<< "$tokens"

                for token in "${token_array[@]}"; do
                    TEMP_ARRAY_TOOL_TOKEN["$token"]="$tool"
                    echo "[UPDATED] TEMP_ARRAY_TOOL_TOKEN: $token -> $tool"
                done
            else
                echo "[WARNING] Tool '$tool' not found in DEPLOYED_TOOL_AGENT."
            fi
        done

        # Debugging: Display tool-token mapping
        echo "  Tool: $tool, Tokens: ${tokens:-None}"
    done < "$cleaned_file"

    # Display Services Found
    echo -e "\n[INFO] Services Found:"
    for port in "${!SERVICES_FOUND[@]}"; do
        echo "  Port $port => Service: ${SERVICES_FOUND[$port]}"
    done

    # Display Tools for Open Ports
    echo -e "\n[INFO] Tools for Open Ports:"
    for service in "${!USED_OPEN_PORTS[@]}"; do
        echo "  Service: $service => Tools: ${USED_OPEN_PORTS[$service]}"
    done

    echo "[SUCCESS] File processing completed."
}


# Initialize dns_server and ip_address 

execute_tools() {



  ip_address="10.10.11.63"

   dns_server="whiterabbit.htb"



# Ip_address variable validation 

if ! [[ "$ip_address" =~ ^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$ ]]; then

    echo "Invalid IP address: $ip_address"

    return

fi

    # Validate DNS server

   if [[ -z "$dns_server" ]]; then

        echo "Error: DNS server is not provided. Skipping DNS-related tools."

        return

    fi


   # Iterate through TEMP_ARRAY_TOOL_TOKEN and execute the corresponding tools

    for token in "${!TEMP_ARRAY_TOOL_TOKEN[@]}"; do

        # Get the corresponding tool name

        tool="${TEMP_ARRAY_TOOL_TOKEN[$token]}"



        # Debug: Print the token and corresponding tool

        echo "Processing Token: $token => Tool: $tool"



            # Execute tools
 case "$tool" in

		 dig)

			echo "DNS service is found ::: Running dig"

			 dig axfr "'@'$dns_server" 
                       wait $!  # Wait for it to complete
                       echo  "Completed"
		      	;;

		 dnsenum)

		       echo "DNS service is found ::: Running dnsenum"

			 dnsenum -enum "$dns_server"
			 wait $!  # Wait for it to complete
                       echo  "Completed"

			;;

	 	

		wpscan)

		# Initialize ghalat var 
check_file="temp.txt"
output_file="$OUTPUT_DIR/wpscan.txt"
# Run WPScan and check if "Scan Aborted" appears
(timeout 6 wpscan --url "http://$dns_server/" >> "$check_file" 2>&1)

if grep -q "Scan Aborted" "$check_file"; then
    ghalat="$(grep "Scan Aborted" "$check_file")"
    echo    -e "\e[1;37;41m$ghalat\e[0m"
    rm -f "$check_file"
else
   echo "Starting aggressive scanning on WordPress website"
 echo  "Running WPScan for WordPress analysis..."
fi

# Extract plugins path from the website
initial_plugins_path=$(curl -s "http://$dns_server/" | grep -oE "/wp-content/plugins/[^/]+" | cut -d '/' -f4 | uniq)

wp_content_plugins_path=""

if [[ -n "$initial_plugins_path" ]]; then
    wp_content_plugins_path="/wp-content/plugins"
     echo   "Plugin path detected: $wp_content_plugins_path"
else
  echo    "Warning: Could not determine plugin path. Proceeding with default."
    wp_content_plugins_path="/wp-content/plugins"
fi

# Execute WPScan with the detected or default path
wpscan --url "http://$dns_server/" --wp-plugins-dir "$wp_content_plugins_path" -e ap,dbe,u,m,vp --plugins-detection aggressive --output "$output_file"
wait $!  # Wait for it to complete
                        echo   "Completed"
                    ;;



  sslyze)

			    echo "Running SSLyze to analyze SSL/TLS configurations."
			    output_file="$OUTPUT_DIR/sslyze.txt"

      if [[ -n "$ip_address" ]]; then

          sslyze --regular "$ip_address" >> "$output_file"

      else

        echo "Error: IP address is not set. Skipping SSLyze."

      fi
wait $!  # Wait for it to complete
                        echo  "Completed"
			 ;;



  gobuste-r)

			     echo  "Starting directory brute force using Gobuster."
output_file="$OUTPUT_DIR/gobuster_dir.txt"
      if [[ -n "$dns_server" && -f "/usr/share/wordlists/rockyou.txt" ]]; then

          gobuster dir -u "http://$dns_server" -w "/usr/share/wordlists/SecLists/rockyou.txt" -t 20 -o "$output_file" -k -r -q

      else

      if [[ -z "$dns_server" ]]; then

       echo "Error: DNS server value is empty. Skipping Gobuster."

      fi

      if [[ ! -f "wordlist.txt" ]]; then

                             

        echo "Error: wordlist.txt file not found. Skipping Gobuster."

      fi

      fi
wait $!  # Wait for it to complete
                        echo   "Completed"
			 ;;



  enum4linux)

			     echo  "Running Enum4Linux for SMB/NetBIOS enumeration."
output_file="$OUTPUT_DIR/enumforlinux.txt"
      if [[ -n "$ip_address" ]]; then
          enum4linux "$ip_address" >> "$output_file"
      else 
       echo  "Error: IP address is empty. Skipping Enum4Linux."
      fi
      wait $!  # Wait for it to complete
                       echo  "Completed"

			 ;;

  snmp-check)

			    echo    "Checking for SNMP vulnerabilities with snmp-check."
			    output_file="$OUTPUT_DIR/snmp_check.txt"
      if [[ -n "$ip_address" ]]; then
          snmp-check "$ip_address" >> "$output_file"
      else
       echo  "Error: IP address is empty. Skipping snmp-check."
      fi
wait $!  # Wait for it to complete
                        echo    "Completed"
			 ;;



  nmap)

			  echo  "Running Nmap CVE enumeration with vulners script."
			  output_file="$OUTPUT_DIR/nmapvulners_scan.txt"

      if [[ -f /usr/share/nmap/scripts/vulners.nse ]]; then

      if [[ -n "$ip_address" && -n "$port_number" ]]; then

                             

         echo  "[RECON CVE] Scanning TCP ports for vulnerabilities."

        nmap -sV --script vulners --script-args mincvss=7.0 -p "$port_number" -o "$output_file" "$ip_address"

      else

     echo "Error: Missing IP address or port for Nmap scan. Skipping Nmap."

      fi

      else

      echo "Error: Nmap vulners script not found. Skipping Nmap."

      fi
wait $!  # Wait for it to complete
                       echo  "Completed"
			 ;;



  impacket)

			 impacket #not done yet :
wait $!  # Wait for it to complete
                        echo   "Completed"
			 ;;



  joomsca-n)

			echo  "Running JoomScan for Joomla vulnerability scanning."
			 output_file="$OUTPUT_DIR/joomscan.txt"

      if [[ -n "$ip_address" ]]; then

        joomscan -u "http://$ip_address/" >> "$output_file"

      else

      echo  "Error: IP address is empty. Skipping JoomScan."

      fi
wait $!  # Wait for it to complete
                     echo "Completed"
			;;



  droopesca-n)

			 echo "Running Droopescan for Drupal vulnerability scanning."
			   output_file="$OUTPUT_DIR/droopescan.txt"

      if [[ -n "$ip_address" ]]; then

      droopescan scan --url "http://$ip_address/" >> "$output_file"

      else

  echo  "Error: IP address is empty. Skipping Droopescan."

      fi
      wait $!  # Wait for it to complete
                      echo   "Completed"
 			 ;;



  impacket)

			 impacket #not done yet : wait $!  # Wait for it to complete // echo    "Completed"

			 ;;




  smbmap)
   local output_file="$OUTPUT_DIR/smbmap_output.txt"
    
    # Only prompt for credentials if SMB is found and anonymous access fails
 echo    "Attempting anonymous SMB login..."
    if ! smbmap -H "$ip_address" >> "$output_file" 2>&1; then
      echo    "Anonymous access failed. Credentials required."
        read -p "Enter SMB username: " smb_username
        read -s -p "Enter SMB password: " smb_password
        
        smbmap -u "$smb_username" -p "$smb_password" -H "$ip_address" >> "$output_file" 2>&1
    fi

			 echo  "Running SMBMap for SMB share enumeration."
			  
wait $!  # Wait for it to complete
                       echo    "Completed"
			 ;;


  redis-exploit)

 echo  "Running Redis Exploit script for enumeration and exploitation."

output_file="$OUTPUT_DIR/redis_exploit_output.txt"

    # Check if the script file exists

    script_path="redis-exploit.py"

    if [[ ! -f "$script_path" ]]; then

   echo  "Error: $script_path not found in the current directory."

     echo    "Please ensure redis-exploit.py is available before running this function."

        return 1

    fi



    # Prompt the user for the target IP address and port

    if [[ -z "$ip_address" ]]; then

        read -p "Enter the target IP address: " ip_address

    fi



    if [[ -z "$redis_port" ]]; then

        read -p "Enter the Redis port default is : 6379 " redis_port

        redis_port=${redis_port:-6379} # Default to 6379 if no port is specified

    fi



    # Execute the Redis exploit script with the provided inputs

    if [[ -n "$ip_address" && -n "$redis_port" ]]; then

        echo    "Running redis-exploit.py against $ip_address on port $redis_port..."

        python3 "$script_path" --target "$ip_address" --port "$redis_port" >> "$output_file" 2>&1

      echo  "Redis exploit completed. Results saved in 'redis_exploit_output.txt'."

    else

   echo  "Error: Missing IP address or port. Skipping Redis exploit."

    fi
wait $!  # Wait for it to complete
                      echo   "Completed"
    ;;



  wfu-zz)

   echo  "Starting Fuzz on Parameter grabbed via in_vs"



    # Ask for the parameter name ( id, username, token)

      read -p "Enter the parameter ,name  id, username: " param

      read -p "Enter the target IP address: " ip_address



    # Determine if the parameter should be fuzzed with words or numbers

      read -p "Is this a word-based parameter or number-based parameter? word/number: " param_type



    # Check and prepare the appropriate wordlist based on the parameter type

      if [[ "$param_type" == "word" ]]; then

       wordlist="/usr/share/wordlists/rockyou.txt"

       if [[ ! -f "$wordlist" ]]; then

                        

      echo  "Error: Wordlist $wordlist not found. Exiting."

        return 1

      fi

    echo   "Running WFuzz with wordlist: $wordlist"

      wfuzz -c -z file,$wordlist -u "http://$ip_address/?$param=FUZZ"

      elif [[ "$param_type" == "number" ]]; then

    # You can create a number-based wordlist or use a range of numbers

      wordlist="/usr/share/wordlists/SecLists/Fuzzing/3-digits-000-999.txt"  # This could be a file like 001, 2000, 3000, ..., 999

      if [[ ! -f "$wordlist" ]]; then

            

 echo  "Error: Number wordlist $wordlist not found. Exiting."

    return 1

     fi

   echo    "Running WFuzz with number wordlist: $wordlist"

         wfuzz -c -z file,$wordlist -u "http://$ip_address/?$param=FUZZ"

        else

   echo   "Invalid parameter type. Please specify 'word' or 'number'."

     return 1

      fi
wait $!  # Wait for it to complete
                   echo    "Completed"
   ;;



  ffuf)
echo "Running FFUF for DNS discovery and directory enumeration"

output_file="$OUTPUT_DIR/subdomain.txt"
dir_output_file="$OUTPUT_DIR/directories.txt"

# Attempt to determine Content-Length for filtering results
length="$(curl -so /dev/null "http://$ip_address/" -H "HOST: defnotvalid.$dns_server" -w '%{size_download}')"

# Check if length is retrieved successfully
if [ -z "$length" ]; then
echo    "Error: Unable to determine Content-Length. Skipping FFUF."
    return 1
fi

# Run FFUF for DNS discovery in a subshell, ensuring the output is saved to the current shell
(
    ffuf -w "/usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt" \
        -u "http://$ip_address/" -H "Host: FUZZ.$dns_server" \
        -fs "$length" -mc "200" -o "$output_file"
) 

# Run FFUF for directory enumeration concurrently
(ffuf -w "/usr/share/wordlists/dirb/common.txt" \
    -u "http://$ip_address/FUZZ" \
    -mc "200,301,302" -o "$dir_output_file"
)
# Wait for the background job (DNS discovery) to finish




echo     "Valuable subdomains found. Proceeding with further analysis."



echo     "Valuable directories found. Proceeding with further analysis."
wait $!  # Wait for it to complete
                     echo     "Completed"
;;


		odat.py)

 echo   "Running odat.py..."



    # Check if odat.py file exists

    if [[ ! -f "odat.py" ]]; then

   echo   "Error: odat.py script not found. Exiting."

        return 1

    fi



    # Define output file for odat.py

    output_file="$OUTPUT_DIR/odat_output.txt"



    # Run odat.py and redirect output to the file

    echo   "Starting odat.py..."

    python3 odat.py >> "$output_file" 2>&1



    # Check if the command ran successfully

    if [[ $? -eq 0 ]]; then

       echo     "odat.py completed successfully. Results saved in $output_file."

    else

     echo    "Error: odat.py execution failed. Check the output in $output_file."

    fi
wait $!  # Wait for it to complete
                      echo    "Completed"
    ;;



                 hydr-a)

echo  "Running Hydra for brute-force attack on POST request."



    # Prompt for the target DNS server if not already provided

    if [[ -z "$dns_server" ]]; then

        read -p "Enter the DNS server or IP address: " dns_server

    fi



    # Check if the endpoint is provided, else prompt for it

    if [[ -z "$endpoint" ]]; then

        read -p "Enter the POST request endpoint  like /login.php: " endpoint

    fi



    # Check if the wordlist is set, else prompt for it

    if [[ -z "$password_wordlist" ]]; then

        read -p "Enter the path to the password wordlist like /passwords.txt: " password_wordlist

    fi



    # Ensure the wordlist exists

    if [[ ! -f "$password_wordlist" ]]; then

    echo    "Error: Password wordlist file not found at $password_wordlist. Exiting."

        return 1

    fi



    # Check if regex for error message is provided, else set a default error message regex

    if [[ -z "$error_regex" ]]; then

        error_regex="Invalid Credentials!"

    fi



    # Define output file for Hydra

    output_file="$OUTPUT_DIR/hydra_output.txt"



    # Run Hydra with the dynamic inputs and save output to a file

   echo     "Starting Hydra brute-force attack on $dns_server using POST method at $endpoint..."

    hydra -l admin -P "$password_wordlist" "$dns_server" http-post-form "$endpoint:username=admin&password=^PASS^:$error_regex" >> "$output_file" 2>&1



    # Check if Hydra ran successfully

    if [[ $? -eq 0 ]]; then

     echo     "Hydra brute-force attack completed. Results saved in $output_file."

    else

  echo    "Error: Hydra brute-force attack failed. Check the output in $output_file."

    fi
wait $!  # Wait for it to complete
                   echo    "Completed"
    ;;



rpcinfo)

  echo   "Running rpcinfo for RPC enumeration."



    # Check if IP address is set, else prompt for it

    if [[ -z "$ip_address" ]]; then

        read -p "Enter the target IP address for RPC enumeration: " ip_address

    fi



    # Define output file for rpcinfo

    output_file="$OUTPUT_DIR/rpcinfo_output.txt"



    # Run rpcinfo with the provided IP address and save output to a file

  echo    "Running rpcinfo on $ip_address to enumerate RPC services..." >> "$output_file"

    rpcinfo "$ip_address" >> "$output_file" 2>&1



    # Check if rpcinfo ran successfully

    if [[ $? -eq 0 ]]; then

       echo     "RPC enumeration completed. Results saved in $output_file."

    else

    echo   "Error: RPC enumeration failed. Check the output in $output_file."

    fi
wait $!  # Wait for it to complete
                     echo    "Completed"
    ;;



                 medusa)

 echo    "Running Medusa for brute-force attack."

output_file="$OUTPUT_DIR/medusa_$service.txt"

    # Check if IP address is set, else prompt for it

    if [[ -z "$ip_address" ]]; then

        read -p "Enter the target IP address: " ip_address

    fi



    # Check if a wordlist is set, else prompt for it

    if [[ -z "$wordlist" ]]; then

        read -p "Enter the path to the wordlist: " wordlist

    fi



    # Ensure the wordlist exists

    if [[ ! -f "$wordlist" ]]; then

     echo    "Error: Wordlist file not found at $wordlist. Exiting."

        return 1

    fi



    # Prompt for the service to brute-force (SSH, FTP, etc.)

    read -p "Enter the service to target like ssh, ftp, smb: " service



    # Run Medusa with the given parameters

    echo    "Starting Medusa brute-force attack on $ip_address for $service service..."

    medusa -h "$ip_address" -u "$username" -P "$wordlist" -M "$service" -t 4 -o "$output_file"



    # Check if Medusa ran successfully

    if [[ $? -eq 0 ]]; then

       echo     "Medusa brute-force completed. Results saved to medusa_results.txt."

    else

  echo   "Error: Medusa brute-force failed. Check the output file for details."

    fi
wait $!  # Wait for it to complete
                       echo     "Completed"
    ;;



johntheripper)

echo    "Running John the Ripper for password cracking."


 output_file="$OUTPUT_DIR/jhondrippr.txt"
    # Check if a hash file is provided, else prompt for it

    if [[ -z "$hash_file" ]]; then

        read -p "Enter the path to the hash file: " hash_file

    fi



    # Ensure the hash file exists

    if [[ ! -f "$hash_file" ]]; then

    echo    "Error: Hash file not found at $hash_file. Exiting."

        return 1

    fi



    # Check if a wordlist is set, else prompt for it

    if [[ -z "$wordlist" ]]; then

        read -p "Enter the path to the wordlist for password cracking: " wordlist

    fi



    # Ensure the wordlist exists

    if [[ ! -f "$wordlist" ]]; then

     echo   "Error: Wordlist file not found at $wordlist. Exiting."

        return 1

    fi



    # Run John the Ripper with the given hash file and wordlist

    echo    "Starting John the Ripper password cracking on $hash_file using $wordlist..."

    john --wordlist="$wordlist" --format=raw-md5 "$hash_file" >> "$output_file"



    # Check if John the Ripper ran successfully

    if [[ $? -eq 0 ]]; then

        echo    "John the Ripper password cracking completed. Results saved to john_results.txt."

    else

  echo    "Error: John the Ripper failed. Check the output file for details."

    fi
wait $!  # Wait for it to complete
                      echo     "Completed"
    ;;



                 smtp_user_enum)

  echo    "Running SMTP User Enumeration."



    # Prompt the user to input the SMTP server and port if not already set

    if [[ -z "$ip_address" ]]; then

        read -p "Enter the SMTP server IP address: " ip_address

    fi

    read -p "Enter the SMTP port ,default 25: " smtp_port

    smtp_port=${smtp_port:-25}



    # Prompt for the wordlist if not provided

    if [[ -z "$wordlist" ]]; then

        read -p "Enter the path to the wordlist for user enumeration: " wordlist

    fi



    # Check if the wordlist file exists

    if [[ ! -f "$wordlist" ]]; then

     echo    "Error: Wordlist file not found at $wordlist. Please provide a valid path."

        return 1

    fi



    # Define the output file

    output_file="$OUTPUT_DIR/smtp_user_enum_results.txt"



    # Run smtp-user-enum tool with the provided parameters

   echo     "Starting SMTP user enumeration on $ip_address:$smtp_port..."

    smtp-user-enum -M VRFY -U "$wordlist" -t "$ip_address" -p "$smtp_port" -o "$output_file" > /dev/null 2>&1



    # Check if the command succeeded

    if [[ $? -eq 0 ]]; then

        echo     "SMTP user enumeration completed successfully. Results saved to $output_file."

    else

    echo     "Error: SMTP user enumeration failed. Check the output file for details."

    fi
wait $!  # Wait for it to complete
                      echo      "Completed"
    ;;



                 nikto)

    echo "Running Nikto Web Application Scanner."



    # Detect protocol (default to HTTP if HTTPS is not detected)

echo   "Checking protocol for $dns_server..."

    if curl -s -k --head "http://$dns_server" | grep -q "200 OK"; then

        protocol="https"

     echo     "Protocol detected: HTTP."

    else

        protocol="http"

     echo     "Defaulting to HTTPS."

    fi


 nikto_output="$OUTPUT_DIR/nikto_results_${protocol}.txt"

        # Run Nikto in a subshell in the background
        ( 
            echo      "Starting Nikto scan on $protocol://$ip_address..."
            nikto -h "$protocol://$dns_server" >> "$nikto_output"
            echo     "Nikto scan completed. Results saved to $nikto_output."
        ) 

       

    echo     "Nikto is running ...."
        wait $!  # Wait for it to complete
                       echo     "Completed"
        ;;






                 mysql-enum)

 echo    "Enumerating MySQL database."



    # Check if IP address is provided

    if [[ -z "$ip_address" ]]; then

    echo     "Error: IP address is not set. Skipping MySQL enumeration."

    else

        # Prompt for MySQL credentials

        if [[ -z "$mysql_username" ]]; then

            read -p "Enter MySQL username: " mysql_username

        fi



        if [[ -z "$mysql_password" ]]; then

            read -sp "Enter MySQL password for $mysql_username: " mysql_password

            echo     # Move to a newLLine after password input

        fi



        # Perform basic enumeration

       echo    "Running MySQL enumeration on $ip_address..."

        mysql_output_file="$OUTPUT_DIR/mysql_enum_results.txt"



        mysql -h "$ip_address" -u "$mysql_username" -p"$mysql_password" -e "SHOW DATABASES;" >> "$mysql_output_file" 2>&1

        if [[ $? -eq 0 ]]; then

            echo      "MySQL enumeration results saved to $mysql_output_file."

        else

         echo    "Failed to enumerate MySQL. Check your credentials or connectivity."

        fi

    fi
wait $!  # Wait for it to complete
                      echo     "Completed"
    ;;



                 mysql)

  echo    "Connecting to MySQL database."



    # Check if IP address is provided

    if [[ -z "$ip_address" ]]; then

    echo    "Error: IP address is not set. Skipping MySQL connection."

    else

        # Prompt for MySQL credentials

        if [[ -z "$mysql_username" ]]; then

            read -p "Enter MySQL username: " mysql_username

        fi



        if [[ -z "$mysql_password" ]]; then

            read -sp "Enter MySQL password for $mysql_username: " mysql_password

            echo     # Move to a new line after password input

        fi



        # Connect to MySQL

    echo    "Connecting to MySQL on $ip_address..."

        mysql -h "$ip_address" -u "$mysql_username" -p"$mysql_password"

        if [[ $? -eq 0 ]]; then

         echo      "MySQL connection successful."

        else

       echo    "Failed to connect to MySQL. Check your credentials or connectivity."

        fi

    fi
wait $!  # Wait for it to complete
                       echo     "Completed"
    ;;



  pg_enum)

   echo   "Enumerating PostgreSQL database."

 output_file="$OUTPUT_DIR/postgresql.txt"

    # Check if IP address is provided

    if [[ -z "$ip_address" ]]; then

    echo    "Error: IP address is not set. Skipping PostgreSQL enumeration."

    else

        # Prompt for PostgreSQL credentials

        if [[ -z "$pg_username" ]]; then

            read -p "Enter PostgreSQL username: " pg_username

        fi



        if [[ -z "$pg_password" ]]; then

            read -sp "Enter PostgreSQL password for $pg_username: " pg_password

            echo     # Move to a new line after password input

        fi



        # Attempt enumeration using `psql` or other tools

      echo    "Running PostgreSQL enumeration on $ip_address..."

        export PGPASSWORD="$pg_password"

        

        # Basic database listing

        psql -h "$ip_address" -U "$pg_username" -c "\l" >> "$output_file" 2>&1

        if [[ $? -eq 0 ]]; then

            echo     "PostgreSQL enumeration results saved to pg_enum_results.txt."

        else

        echo     "Failed to enumerate PostgreSQL. Check your credentials or connectivity."

        fi

    fi
wait $!  # Wait for it to complete
                      echo     "Completed"
    ;;



	        rdp-sec-check)

  echo    "Checking RDP security settings."

output_file="$OUTPUT_DIR/rdp_sec_check_results.txt"

    # Check if IP address is provided

    if [[ -z "$ip_address" ]]; then

     echo    "Error: IP address is not set. Skipping RDP security check."

    else

    echo      "Running RDP security check on $ip_address..."



        # Ensure the required tool (e.g., rdpscan) is installed

        command -v rdpscan >/dev/null 2>&1

        if [[ $? -eq 0 ]]; then

            # Perform the security check

            rdpscan "$ip_address" >> "$output_file" 2>&1

            

            if [[ $? -eq 0 ]]; then

              echo      "RDP security check results saved to rdp_sec_check_results.txt."

            else

             echo    "RDP security check failed. Verify the tool and connectivity."

            fi

        else

        echo    "Error: rdpscan is not installed. Please install it and try again."

        fi

    fi
wait $!  # Wait for it to complete
                       echo     "Completed"
    ;;



		 xrdp)

echo  "Checking Remote Desktop Protocol (RDP) service with xrdp."



    # Check if the IP address is provided

    if [[ -z "$ip_address" ]]; then

     echo    "Error: IP address is not set. Skipping xrdp."

    else

    echo      "Attempting to connect to RDP on $ip_address..."

        

        # Use xfreerdp (commonly used for RDP connections)

        command -v xfreerdp >/dev/null 2>&1

        if [[ $? -eq 0 ]]; then

            xfreerdp /v:"$ip_address" /u:"$rdp_username" /p:"$rdp_password" +clipboard +fonts

        else

         echo     "Error: xfreerdp is not installed. Please install it and try again."

        fi

    fi
wait $!  # Wait for it to complete
                    echo    "Completed"
    ;;

  redis-brute)

    echo     "Running brute force attack on Redis service."

output_file="$OUTPUT_DIR/redis_brute_results.txt"

    # Check if IP address is provided

    if [[ -z "$ip_address" ]]; then

    echo     "Error: IP address is not set. Skipping Redis brute force."

    else

        # Prompt for a wordlist if not defined

        if [[ -z "$wordlist" ]]; then

            read -p "Enter the path to your Redis wordlist: " wordlist

        fi



        # Validate wordlist existence

        if [[ -f "$wordlist" ]]; then

           echo     "Starting brute force attack on Redis at $ip_address with wordlist $wordlist..."

            

            # Run a Redis brute force tool like `hydra`

            hydra -L "$wordlist" -P "$wordlist" "$ip_address" redis -vV -o "$output_file"

            

           echo    "Brute force results saved to redis_brute_results.txt."

        else

         echo   "Error: Wordlist '$wordlist' does not exist. Skipping Redis brute force."

        fi

    fi
wait $!  # Wait for it to complete
                      echo    "Completed"
    ;;

                 vncviewer)

  echo   "Running VNC Viewer for remote desktop access."

output="$OUTPUT_DIR/vncviewer.txt"

    # Prompt the user for the target IP and port

    if [[ -z "$ip_address" ]]; then

        read -p "Enter the target IP address for VNC Viewer: " ip_address

    fi



    if [[ -z "$vnc_port" ]]; then

        read -p "Enter the VNC port default is 5900: " vnc_port

        vnc_port=${vnc_port:-5900} # Default to 5900 if no port is entered

    fi



    # Attempt to connect using VNC Viewer

    if [[ -n "$ip_address" && -n "$vnc_port" ]]; then

        echo     "Connecting to VNC server at $ip_address:$vnc_port..."

        vncviewer "$ip_address:$vnc_port" >> "$output_file" 2>&1

       echo    "VNC Viewer session logs saved in 'vncviewer_output.txt'."

    else

    echo   "Error: Missing IP address or port. Skipping VNC Viewer."

    fi
wait $!  # Wait for it to complete
                     echo     "Completed"
    ;;



                 flask-scan)

 echo  "Running Flask Scan for potential vulnerabilities in Flask web applications."

output_file="$OUTPUT_DIR/flask_scan.txt"

    # Prompt the user for the target URL

    if [[ -z "$target_url" ]]; then

        read -p "Enter the target Flask application URL: " target_url

    fi



    # Run Flask Scan only if a target URL is provided

    if [[ -n "$target_url" ]]; then

     echo     "Scanning $target_url with Flask-Scan..."

        flask-scan --url "$target_url" --output "flask_scan_report.txt" >> "$output_file" 2>&1

       echo     "Flask Scan completed. Report saved in 'flask_scan_report.txt', logs in 'flask_scan.log'."

    else

     echo    "Error: No target URL provided. Skipping Flask Scan."

    fi
wait $!  # Wait for it to complete
                       echo      "Completed"
    ;;



  xeyes)

   echo   "Running xeyes..."

    

    # Define output file for xeyes

    output_file="$OUTPUT_DIR/xeyes_output.txt"

    

    # Run xeyes and redirect output to the file

    echo      "Starting xeyes..."

    xeyes >> "$output_file" 2>&1 &  # Background process



    # Check if the command ran successfully

    if [[ $? -eq 0 ]]; then

        echo      "xeyes started successfully. Logs saved in $output_file."

    else

     echo     "Error: xeyes execution failed. Check the output in $output_file."

    fi
wait $!  # Wait for it to complete
                       echo    "Completed"
    ;;

    

  xclock)

   echo    "Running xclock..."



    # Define output file for xclock

    output_file="$OUTPUT_DIR/xclock_output.txt"

    

    # Run xclock and redirect output to the file

    echo     "Starting xclock..."

    xclock >> "$output_file" 2>&1 &  # Background process



    # Check if the command ran successfully

    if [[ $? -eq 0 ]]; then

        echo     "xclock started successfully. Logs saved in $output_file."

    else

     echo   "Error: xclock execution failed. Check the output in $output_file."
        fi

    wait $!  # Wait for it to complete
                       echo     "Completed"
    ;;



  x11-brute)

  echo     "Running X11 Brute Force Attack..."



    # Define output file for x11-brute

    output_file="$OUTPUT_DIR/x11-brute_output.txt"

    

    # Run x11-brute and redirect output to the file

    echo      "Starting x11-brute..."

    x11-brute >> "$output_file" 2>&1 &  # Background process



    # Check if the command ran successfully

    if [[ $? -eq 0 ]]; then

      echo      "x11-brute started successfully. Logs saved in $output_file."

    else

   echo     "Error: x11-brute execution failed. Check the output in $output_file."

    fi
wait $!  # Wait for it to complete
                       echo      "Completed"
    ;;

  sqlma-p)

    echo    "Running SQLMap for SQL injection testing."

output_file="$OUTPUT_DIR/sqlmap.txt"

    # Prompt user for target URL if not provided

    if [[ -z "$target_url" ]]; then

        read -p "Enter the target URL for SQLMap: " target_url

    fi



    # Run SQLMap only if the target URL is provided

    if [[ -n "$target_url" ]]; then

   echo     "Running SQLMap on $target_url..."

        sqlmap -u "$target_url" --batch >> "$output_file" 2>&1

      echo     "SQLMap results saved in the 'sqlmap_output' directory and logged in 'sqlmap.log'."

    else

 echo     "Error: No target URL provided. Skipping SQLMap."

    fi
wait $!  # Wait for it to complete
                      echo    "Completed"
	 		;;

    vhost)

   echo   "Running Virtual Host Discovery (VHost)."

output="$OUTPUT_DIR/vhost_output.txt"

    # Prompt user for domain name if not already set

    if [[ -z "$dns_server" ]]; then

      read -p "Enter the DNS domain name for VHost discovery: " dns_server

    fi



    # Run the vhost discovery only if the DNS domain name is provided

    if [[ -n "$dns_server" ]]; then

   echo      "Searching for virtual hosts on $dns_server..."

        wfuzz -c -z file,/usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -u "http://$dns_server" -H "Host: FUZZ.$dns_server" >> "$output_file" 2>&1

    echo     "VHost discovery results saved in 'vhost_output.txt'."

    else

   echo    "Error: No DNS domain name provided. Skipping VHost discovery."

    fi
wait $!  # Wait for it to complete
                     echo    "Completed"
	 		;;

  whatwe-b)

			echo     "Running WhatWeb for STACK Discovery"

       output="$OUTPUT_DIR/whatweb_results.txt"
    
    if [  "$dns_server" != '' ]; then 

 echo    "Running WhatWeb with provided IP address."

        whatweb "http://$dns_server" >>  "$output" 

    fi
wait $!  # Wait for it to complete
                    echo     "Completed"
		 	;;

  searchsploit)

  echo  "Running SearchSploit for exploit lookup."
 output_file="$OUTPUT_DIR/searchsploit_results.txt"


    # Prompt the user for a search term if not already provided

    if [[ -z "$search_term" ]]; then

        read -p "Enter a search keyword: " search_term

    fi



    # Check if the search term is not empty

    if [[ -n "$search_term" ]]; then

        echo    "Searching exploits for '$search_term'..."

        

        # Execute the SearchSploit command and save the results to a file

       

        searchsploit "$search_term" >> "$output_file" 2>&1

        

        # Display the results and save to a file

      echo    "Search results saved to '$output_file'."

  echo     "Review the file for detailed exploit information."

    else

     echo    "Error: No search term provided. Skipping SearchSploit."

    fi
wait $!  # Wait for it to complete
                      echo    "Completed"
    ;;

  rpcclient)

 echo   "Running rpcclient for SMB enumeration."


      output_file="$OUTPUT_DIR/rpcclient_stdr.txt"
      
    # Check if the IP address is provided

    if [[ -n "$ip_address" ]]; then

     echo    "Enumerating SMB shares on $ip_address using rpcclient..."

        rpcclient -U "" -N "$ip_address" -c "srvinfo" >> "$output_file" 2>&1 # Save output to file

    else

    echo   "Error: IP address is empty. Skipping rpcclient." >> "$output_file"

    fi
wait $!  # Wait for it to complete
                      echo     "Completed"
    ;;

  evil-winrm)

   echo   "Running Evil-WinRM..."



    # Ensure required parameters are provided

    if [[ -z "$winrm_host" || -z "$winrm_user" || -z "$winrm_pass" ]]; then

     echo    "Error: Missing required parameters for Evil-WinRM. Please ensure WinRM host, user, and password are provided."

        return 1

    fi



    # Define dynamic output file for Evil-WinRM logs

    output_file="$OUTPUT_DIR/evil_winrm_output_$(date +%F_%T).txt"



    # Run Evil-WinRM and redirect output

 echo     "Attempting to connect to $winrm_host via Evil-WinRM..."



    evil-winrm -i "$winrm_host" -u "$winrm_user" -p "$winrm_pass" >> "$output_file" 2>&1



    # Check if the command ran successfully

    if [[ $? -eq 0 ]]; then

  echo     "Evil-WinRM connection successful. Running 'whoami' command..."



        # Redirect and run 'whoami'

  echo     "Running 'whoami' to check the current user..."

        evil-winrm -i "$winrm_host" -u "$winrm_user" -p "$winrm_pass" -command "whoami" >> "$output_file"



        # Check the result

        echo     "User information saved in $output_file."

    else

   echo    "Error: Evil-WinRM connection failed. Check the logs in $output_file."

    fi
wait $!  # Wait for it to complete
                     echo    "Completed"
    ;;



redis-cli)

echo   "Running Redis-CLI..."



    # Ensure required parameters are provided

    if [[ -z "$redis_host" || -z "$redis_port" ]]; then

    echo    "Error: Missing required parameters for Redis-CLI. Please ensure Redis host and port are provided."

        return 1

    fi



    # Define dynamic output file for Redis-CLI logs

    output_file="$OUTPUT_DIR/redis_cli_output_$(date +%F_%T).txt"



    # Run Redis-CLI and capture output

   echo     "Connecting to Redis at $redis_host:$redis_port..."

    redis-cli -h "$redis_host" -p "$redis_port" info >> "$output_file" 2>&1



    # Check if the command ran successfully

    if [[ $? -eq 0 ]]; then

   echo      "Redis connection successful. Information saved in $output_file."

    else

   echo  "Error: Redis-CLI connection failed. Check the logs in $output_file."

    fi
wait $!  # Wait for it to complete
                     echo    "Completed"
    ;;



  mssql-scriptor)

    echo  "Running MSSQL Scriptor..."



    # Ensure required parameters are provided

    if [[ -z "$mssql_host" || -z "$mssql_user" || -z "$mssql_pass" ]]; then

echo   "Error: Missing required parameters for MSSQL Scriptor. Please ensure MSSQL host, user, and password are provided."

      return 1

    fi



    # Define dynamic output file for MSSQL Scriptor logs

    output_file="$OUTPUT_DIR/mssql_scriptor_output_$(date +%F_%T).txt"



 echo      "Running MSSQL Scriptor with the following parameters:"

echo      "Host: $mssql_host"

echo    "User: $mssql_user"



    # Start MSSQL Scriptor and capture output

    mssql-scriptor -H "$mssql_host" -U "$mssql_user" -P "$mssql_pass" >> "$output_file" 2>&1



    # Check if the command ran successfully

    if [[ $? -eq 0 ]]; then

       echo     "MSSQL Scriptor completed successfully. Logs saved in $output_file."

    else

  echo    "Error: MSSQL Scriptor execution failed. Check the logs in $output_file."

    fi
wait $!  # Wait for it to complete
                      echo   "Completed"
    ;;



sqlcm-d)

  echo     "Running SQLCMD..."



    # Ensure required parameters are provided

    if [[ -z "$sql_host" || -z "$sql_user" || -z "$sql_pass" ]]; then

   echo    "Error: Missing required parameters for SQLCMD. Please ensure SQL host, user, and password are provided."

        return 1

    fi



    # Define dynamic output file for SQLCMD logs

    output_file="$OUTPUT_DIR/sqlcmd_output_$(date +%F_%T).txt"



echo      "Running SQLCMD with the following parameters:"

  echo     "Host: $sql_host"

echo      "User: $sql_user"



    # Start SQLCMD and capture output

    sqlcmd -S "$sql_host" -U "$sql_user" -P "$sql_pass" >> "$output_file" 2>&1



    # Check if the command ran successfully

    if [[ $? -eq 0 ]]; then

      echo   "SQLCMD completed successfully. Logs saved in $output_file."

    else

echo "Error: SQLCMD execution failed. Check the logs in $output_file."

    fi
wait $!  # Wait for it to complete
                      echo    "Completed"
    ;;



  dns-recon)

    echo  "Running DNS Recon for DNS enumeration."



    # Define the output file

    output_file="$OUTPUT_DIR/dns-recon_output.txt"



    # Check if the IP address or DNS server is provided

    if [[ -n "$dns_server" ]]; then

  echo   "Enumerating DNS records for $dns_server..."

        dns-recon -d "$dns_server" -t std -a >> "$$output_file" 2>&1 # Save output to file for standard enumeration

    else

     echo   "Error: DNS server is empty. Skipping DNS Recon." >> "$output_file"

    fi
wait $!  # Wait for it to complete
                       echo    "Completed"
    ;;



  nslookup)

  echo  "Running NSLookup for DNS query."

         output_file="$OUTPUT_DIR/nslookup_output.txt"

    # Check if the DNS server is provided

    if [[ -n "$dns_server" ]]; then

echo   "Performing NSLookup for DNS server: $dns_server"

        nslookup "$dns_server" >> "$output_file" 2>&1 # Save output to file

    else

     echo   "Error: DNS server is empty. Skipping NSLookup." >> "$output_file"

    fi
wait $!  # Wait for it to complete
                     echo   "Completed"
    ;;



  kerbrute)

    echo   "Running Kerbrute for Kerberos Brute Force Attack..."



    # Ensure required parameters are provided

    if [[ -z "$domain" || -z "$username_list" || -z "$password_list" ]]; then

     echo   "Error: Missing required parameters for Kerbrute. Please ensure domain, username list, and password list are provided."

        return 1

    fi



    # Define dynamic output file for Kerbrute logs

    output_file="$OUTPUT_DIR/kerbrute_output_$(date +%F_%T).txt"

    

 echo    "Running Kerbrute with the following parameters:"

 echo    "Domain: $domain"

 echo   "Username List: $username_list"

 echo    "Password List: $password_list"

    

    # Start Kerbrute brute-force attack and capture output

    kerbrute brute -d "$domain" -U "$username_list" -P "$password_list" -t 10 >>"$output_file" 2>&1



    # Check if the command ran successfully

    if [[ $? -eq 0 ]]; then

        echo    "Kerbrute brute-force completed successfully. Logs saved in $output_file."

    else

   echo "Error: Kerbrute execution failed. Check the logs in $output_file."

    fi
wait $!  # Wait for it to complete
                      echo    "Completed"
    ;;



kinit)

echo   "Running kinit for Kerberos authentication..."



    # Ensure username is provided for kinit

    if [[ -z "$username" ]]; then

    echo "Error: Missing username for kinit. Please provide a valid username."

        return 1

    fi



    # Define dynamic output file for kinit logs

    output_file="$OUTPUT_DIR/kinit_output_$(date +%F_%T).txt"

    

 echo   "Running kinit with username: $username"

    

    # Start kinit and capture verbose output

    kinit "$username" -V >> "$output_file" 2>&1



    # Check if kinit ran successfully

    if [[ $? -eq 0 ]]; then

      echo   "kinit completed successfully. Logs saved in $output_file."

    else

   echo  "Error: kinit execution failed. Check the logs in $output_file."

    fi
wait $!  # Wait for it to complete
                       echo     "Completed"
    ;;



  ldapsearch)

    echo  "LDAP service is found ::: Running ldapsearch"



    # Checking if the IP address is provided

    if [[ -z "$ip_address" ]]; then

   echo   "Error: IP address is empty. Skipping ldapsearch."

        return 1

    fi



    # Running ldapsearch command

    ldapsearch -x -H "ldap://$ip_address" -b "dc=example,dc=com" -D "cn=admin,dc=example,dc=com" -w "password"
wait $!  # Wait for it to complete
                       echo    "Completed"
    ;;



ldapbrute)

   echo  "LDAP Brute Force is found ::: Running ldapbrute"



    # Checking if the IP address is provided

    if [[ -z "$ip_address" ]]; then

     echo   "Error: IP address is empty. Skipping ldapbrute."

        return 1

    fi



    # Ensure the wordlist file exists

    if [[ ! -f "wordlist.txt" ]]; then

    echo    "Error: wordlist.txt not found. Exiting."

        return 1

    fi



    # Running ldapbrute with a defined wordlist

    ldapbrute -H "ldap://$ip_address" -D "cn=admin,dc=example,dc=com" -w "password" -f "wordlist.txt"
wait $!  # Wait for it to complete
                      echo   "Completed"
    ;;



	crackmapexec)

echo    "Running CrackMapExec for SMB enumeration."



    # Define the output file

    output_file="$OUTPUT_DIR/crackmapexec_output.txt"



    # Prompt the user to enter a username and password if not provided

    if [[ -z "$smb_username" ]]; then

        read -p "Enter SMB username: " smb_username

    fi



    if [[ -z "$smb_password" ]]; then

        read -sp "Enter SMB password for $smb_username: " smb_password

        echo     # To move to a new line after password input

    fi



    # Check if the IP address is not empty

    if [[ -n "$ip_address" ]]; then

        # Try guest login (anonymous login)

      echo  "Attempting anonymous SMB login..."

        crackmapexec smb "$ip_address" -u "$smb_username" -p "$smb_password" >> "$output_file" 2>&1 # Save output to file # Guest login (anonymous login)



        # Try with a specific username and password

      echo    "Attempting SMB login with username '$smb_username'..."

        crackmapexec smb "$ip_address" -u "$smb_username" -p "$smb_password" >> "$output_file" 2>&1 # Save output to file # Username and password login

    else

     echo   "Error: IP address is empty. Skipping CrackMapExec." >> "$output_file"

    fi
wait $!  # Wait for it to complete
                       echo    "Completed"
    ;;



  smb-enum-shares)

echo    "Running SMB Share enumeration using smb-enum-shares."



    # Define the output file

    output_file="$OUTPUT_DIR/smb-enum-shares_output.txt"



    # Check if the IP address is not empty

    if [[ -n "$ip_address" ]]; then

        # Run smb-enum-shares enumeration

       echo   "Enumerating SMB shares on $ip_address..."

        smb-enum-shares -u "$smb_username" -p "$smb_password" -H "$ip_address" >> "$output_file" 2>&1 # Save output to file

    else

     echo  "Error: IP address is empty. Skipping SMB Share enumeration." >> "$output_file"

    fi
wait $!  # Wait for it to complete
                       echo    "Completed"
    ;;



  smbclient) # smbclient command NOOOOOOT DOOOONE YEEEEEEEET

 echo    "SMB client is found ::: Running smbclient now"

    

    # Checking if the IP address is provided

       if [[ -z "$ip_address" ]]; then

 echo  "Error: IP address is empty. Skipping SMBClient."

          return 1

       fi



    # Run smbclient command NOOOOOOT DOOOONE YEEEEEEEET

      smbclient -L "$ip_address" -U "guest" -N
wait $!  # Wait for it to complete
                      echo    "Completed"
      ;;



  ssh)

 echo    "SSH service is found ::: Running SSH Banner Grab"

# Check if the IP address is provided
if [[ -z "$ip_address" ]]; then
  echo  "Error: IP address is empty. Skipping SSH Banner Grab."
    exit 1
fi

# Run SSH banner grab with netcat
banner_ssh=$(nc -nv "$ip_address" 22 2>&1 | head -n 1)

# Output the SSH banner
echo  "SSH Banner Grab Output:"
echo   "$banner_ssh"
wait $!  # Wait for it to complete
                      echo    "Completed"

       ;;



  telnet)

 echo   "Telnet service is found ::: Checking for SMTP misconfiguration before attempting Telnet"

    

   # Checking if the IP address is provided

        if [[ -z "$ip_address" ]]; then

  echo  "Error: IP address is empty. Skipping Telnet."

        return 1

     fi

    

   # SMTP misconfiguration check before attempting Telnet

  echo   "Checking for SMTP misconfiguration..."

     smtp_misco="$(nmap -sV -sC -p 25 "$ip_address")"

   # Checking if there's any misconfiguration regarding SMTP

    if [[ -z "$smtp_misco" ]]; then

 echo  "No misconfiguration concerning SMTP."

       else

echo "SMTP misconfiguration detected. Attempting Telnet connection to SMTP (Port 25)"

     telnet "$ip_address" "25" 

    fi
wait $!  # Wait for it to complete
                      echo    "Completed"
  ;;

  ftp)

   echo     "FTP service is found ::: Running FTP command"

    

   # Checking if the IP address is provided

    if [[ -z "$ip_address" ]]; then

  echo   "Error: IP address is empty. Skipping FTP."

        return 1

      fi

      

# Running FTP command to upload a test file

            ftp -inv "$ip_address" <<EOF

put test.txt

EOF
wait $!  # Wait for it to complete
                      echo    "Completed"
;; 

    esac

done


   log "execute_tools: Running tools..." "INFO"

    
   
}






log "Welcome to NetReconX." "ENJOY"
net() {
    # Main script execution
    echo "🚀 Starting script execution..."

    # Step 1: Run tooler
    echo "🔧 Running tooler..."
    if tooler "$1" "$2"; then
        echo "✅ tooler completed successfully."
    else
        echo "❌ tooler failed. Exiting script."
        return 1
    fi

    # Step 2: Run file_cleaner
    echo "🧹 Running file_cleaner..."
    cleaned_file=$(file_cleaner)
    if [[ -n "$cleaned_file" ]]; then
        echo "✅ file_cleaner completed successfully. Cleaned file: $cleaned_file"
    else
        echo "❌ file_cleaner failed. Exiting script."
        return 1
    fi

    # Step 3: Run file_processor
    echo "🔍 Running file_processor..."
    if file_processor "$cleaned_file"; then
        echo "✅ file_processor completed successfully."
    else
        echo "❌ file_processor failed. Exiting script."
        return 1
    fi

    # Step 4: Run execute_tools
    echo "🛠️ Running execute_tools..."
    if execute_tools; then
        echo "✅ execute_tools completed successfully."
    else
        echo "❌ execute_tools failed. Exiting script."
        return 1
    fi

    # Step 5: Run Investigator (only once)
    echo "🕵️ Running Investigator..."
    if Investigator; then
        echo "✅ Investigator completed successfully."
    else
        echo "❌ Investigator failed. Exiting script."
        return 1
    fi



}


net "$1" "$2" 
