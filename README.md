# NetReconX - Network Reconnaissance Tool

![NetReconX Banner](banner.png)


<p align="center">
  <img src="https://img.shields.io/badge/version-1.0.0-blue.svg" alt="Version">
  <img src="https://img.shields.io/badge/bash-4.0%2B-brightgreen.svg" alt="Bash Version">
  <img src="https://img.shields.io/badge/license-MIT-yellow.svg" alt="License">
</p>

<p align="center">
  Advanced Network Reconnaissance and Security Assessment Tool
</p>

## Overview

NetReconX is a powerful network reconnaissance and security assessment tool written in Bash. It provides a comprehensive suite of tools for network scanning, service enumeration, vulnerability assessment, and security testing, with the ability to postpone scans and manage their execution flow.

## Features

- 🎯 **Multi-stage Network Scanning**: Progressive scanning from basic discovery to advanced exploitation
- 🔍 **Service Enumeration and Version Detection**: Detailed service identification and analysis
- 🛡️ **Vulnerability Assessment**: Identify security weaknesses in target systems
- 📊 **Automated Tool Execution**: Based on discovered services and ports
- 📝 **Detailed Logging and Reporting**: Comprehensive output of scan results
- 🎨 **Interactive CLI Interface**: User-friendly with colorful, animated outputs
- 🔄 **Task Postponement System**: Schedule scans to run later or pause for manual execution
- 🛠️ **Modular and Extensible Architecture**: Easy integration of new tools
- ⚙️ **Configurable Scanning Stages**: Customize scan intensity and focus

## Prerequisites

- Bash 4.0+
- Common security tools (see Dependencies section)
- Root/sudo privileges (for certain operations)

## Dependencies

NetReconX relies on several security tools for its functionality:

### Core Dependencies
- `nmap` - Network scanning and service detection
- `curl` - HTTP requests and data transfer
- `grep`, `awk`, `sed` - Text processing
- `tput` - Terminal control

### Security Tools (based on actual script usage)
- `hydra` - Password cracking and brute force
- `smbmap`, `smbclient`, `enum4linux` - SMB enumeration
- `rpcclient` - RPC client for SMB
- `droopescan` - Drupal vulnerability scanning
- `mysql` - MySQL client
- `xfreerdp` - RDP client
- `evil-winrm` - WinRM client
- `kinit` - Kerberos authentication

### Optional Dependencies (supported in script)
- Additional tools for specialized scanning as needed

## Installation

1. Clone or download the script:
```bash
git clone https://github.com/yourusername/NetReconX.git
cd NetReconX
```

2. Make the script executable:
```bash
chmod +x NetReconX.sh
```

3. Create a basic configuration file:
```bash
touch config.cfg
```

4. Install required dependencies:
```bash
sudo apt-get update
sudo apt-get install nmap curl hydra smbclient enum4linux
# Install other dependencies as needed for your specific scanning requirements
```

## Basic Usage

```bash
sudo ./NetReconX.sh
```

The tool will display an animated banner and initialize. It requires a configuration file (`config.cfg`) in the same directory as the script.

### Running Postponed Tools

```bash
sudo ./NetReconX.sh --run-postponed
```

This command will check for and run any previously postponed scans.

### Scanning Stages

NetReconX uses a staged approach to scanning:

```bash
sudo ./NetReconX.sh <stage> <target>
```

Where:
- `stage`: The scanning stage (0-3)
- `target`: Target IP address or hostname

#### Stage 0: Initial Discovery
- Host discovery
- Basic port scanning
- Service detection

#### Stage 1: Service Enumeration
- Detailed service version detection
- OS fingerprinting
- Script scanning

#### Stage 2-3: Advanced Testing
- Vulnerability assessment
- Brute force testing
- Service-specific scanning

## Available Tools

NetReconX integrates numerous security assessment tools, including:

1. **Network Scanning**
   - Nmap with multiple scan techniques
   - Host discovery
   - Port scanning
   - Service detection
   - OS fingerprinting

2. **Web Assessment**
   - URL and HTML content fetching
   - Link extraction
   - Form field analysis
   - Web service enumeration
   - CMS scanning (like Droopescan for Drupal)

3. **Authentication Testing**
   - SMB authentication (smbmap, smbclient)
   - Remote Desktop Protocol (RDP) testing
   - Kerberos authentication (kinit)
   - Windows Remote Management (Evil-WinRM)

4. **Service-Specific Tools**
   - rpcclient for SMB/RPC enumeration
   - mysql connections
   - ssh authentication

## Tool Organization

NetReconX uses associative arrays to organize various scanning options:

```bash
HOST_DISCOVERY_OPTIONS=(
  ["List_Scan"]="-sL"
  ["Treat_All_Hosts_As_Online"]="-Pn"
  ["TCP_SYN_Discovery"]="-PS"
  ["UDP_Discovery"]="-PU"
  ["SCTP_Discovery"]="-PY"
  ["System_DNS"]="--system-dns"
  ["Traceroute"]="--traceroute"
)

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

PORT_SPECIFICATION_OPTIONS=(
  ["thsd_PORT_RANGES"]="-p 21-81"
  ["FAST_MODE"]="-F"
  ["OPEN_PORTS"]="--open"
  ["UNASSIGNED_ASSIGNED_PORTS"]="-p-"
)
```

These options can be combined to create customized scanning profiles.

## Tool Integration Guide for Developers

### Adding New Tools

To add a new tool to NetReconX:

1. Add a new case statement in the `tooler()` function:

```bash
your_new_tool_name)
    echo "Running your new tool..."
    
    # Tool implementation here
    # For example:
    output_file="$OUTPUT_DIR/your_tool_output.txt"
    your_tool_command "$target" > "$output_file"
    
    # Wait for completion and cleanup
    wait $!
    echo "Completed"
    
    # Remove from postponed list if applicable
    if [[ -n "${POSTPONED_TOOLS[$tool]}" ]]; then
        unset "POSTPONED_TOOLS[$tool]"
        unset "TOOL_STATUS[$tool]"
        save_postponed_state
    fi
    ;;
```

2. For service-based tools, add them to the `DEPLOYED_TOOL_AGENT` array:
```bash
DEPLOYED_TOOL_AGENT=(
    ["your_tool"]="TOOL_ID"
    # Existing tools...
)
```

3. Map the tool to specific services in the `DEMARCHE` array:
```bash
DEMARCHE=(
    ["service_name"]="your_tool,other_tools"
    # Existing mappings...
)
```

### Tool Template

Here's a template for adding a new tool:

```bash
new_tool_name)
    echo "Running new tool against target..."
    
    # Check for required parameters
    if [[ -z "$ip_address" ]]; then
        echo "Error: IP address is empty. Skipping new tool."
        return 1
    fi
    
    # Define output file
    output_file="$OUTPUT_DIR/new_tool_output.txt"
    
    # Run the tool command
    new_tool_command -t "$ip_address" -o "$output_file"
    
    # Check for successful execution
    if [[ $? -eq 0 ]]; then
        echo "New tool completed successfully. Output saved to $output_file"
    else
        echo "Error: New tool execution failed."
    fi
    
    # Cleanup
    wait $!
    echo "Completed"
    
    # Remove from postponed list
    if [[ -n "${POSTPONED_TOOLS[$tool]}" ]]; then
        unset "POSTPONED_TOOLS[$tool]"
        unset "TOOL_STATUS[$tool]"
        save_postponed_state
    fi
    ;;
```

### Adding New Scanning Stages

To add a new scanning stage:

1. Create a new stage array:
```bash
STAGE_X=(
    ["option1"]="${SOME_OPTION}"
    ["option2"]="${ANOTHER_OPTION}"
)
```

2. Add the stage to the case statement in the `tooler` function:
```bash
case $stage in
    X)
        log "Starting Stage X scan."
        for option_group in "${!STAGE_X[@]}"; do
            option="${STAGE_X[$option_group]}"
            scan_options+="$option "
        done
        ;;
    # Existing stages...
esac
```

### Configuration File

The `config.cfg` file can include variables to customize your scanning experience:

```bash
# Log file
LOG_FILE="netreconx.log"

# Input XML and JSON files
XML_FILE="${tooler_output_files["xml"]}"
JSON_FILE="${tooler_output_files["json"]}"


```

### Handling Postponed Tools

NetReconX includes a system for postponing tools:

1. The user can postpone a tool when prompted
2. Tools can be postponed for a specific time period or for manual execution later
3. The state is saved to `postponed_tools.state`
4. Postponed tools can be run using `--run-postponed`

## Output Structure

Results are saved in the following directories:
- `./output_dir/`: Main output directory for tool results
- `./dumped_html/`: Directory for HTML content dumps from web scanning
- Log files with timestamps for debugging and record-keeping

## Security Considerations

⚠️ **IMPORTANT**: This tool is for authorized security testing only. Always:
- Obtain proper authorization before scanning any network
- Be aware that some scanning techniques can be disruptive or trigger security alerts
- Handle credentials and sensitive information carefully
- Review scan outputs for sensitive data before sharing
- Use responsibly and ethically
- Follow applicable laws and regulations

## Troubleshooting

### Common Issues

1. **Tool Errors**: Ensure all required tools are installed and in your PATH
2. **Permission Errors**: Some scans require root/sudo privileges
3. **Missing Configuration**: The script expects `config.cfg` in the same directory
4. **Output Directory Issues**: Ensure the script can create/write to the output directory

### Debugging

Enable DEBUG_MODE in the config file to see more detailed logs:

```bash
DEBUG_MODE=true
```

Check the log file for detailed information:

```bash
cat netreconx.log
```

## Contributing

Contributions to NetReconX are welcome! To contribute:

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## Roadmap

- [ ] Dynamic IP/DNS configuration
- [ ] Web interface for scan management
- [ ] More tool integrations
- [ ] Enhanced reporting capabilities
- [ ] Automated vulnerability correlation

## Disclaimer

This tool is provided for educational and authorized security testing purposes only. The authors are not responsible for any misuse or damage caused by this program.


