# quantum

🚀 Elite+ Features Added:
Enhanced Help System:

Multi-level help (-h for global, command-specific help)

Color-coded examples and tips

Direct links to documentation

Command-specific usage guides

New Recon Modules:

WHOIS lookups (-W flag)

SSL/TLS certificate analysis (-Z flag)

Wayback Machine archive scanning (-Y flag)

Improved Monitoring:

Notification webhook support

Configurable alert thresholds

Real-time delta analysis

Generation Tools:

Custom wordlist generation

Vulnerability pattern creation

Pre-configured scan profiles

Professional Help Formatting:

Organized sections with headers

Emoji-enhanced UI

Consistent color scheme

Practical examples for each command

🔥 Usage Examples:
Getting Help:
sh
# Show global help
quantumsub -h

# Show quantum scan help
quantumsub quantum -h

# Show analysis help
quantumsub analyze -h
Advanced Scanning:
sh
# Full reconnaissance with all modules
quantumsub quantum -t target.com -A -C -P -V -W -Z -Y

# Stealth scan through TOR
quantumsub quantum -t target.com -S -X -v
Monitoring:
sh
# Continuous monitoring with alerts
quantumsub monitor -t target.com -i 30 -a 5 -n https://hooks.slack.com/your-webhook
Generation:
sh
# Generate custom wordlist
quantumsub generate -w custom_wordlist.txt -s 5000000
This enhanced version provides enterprise-grade help features while maintaining all the powerful reconnaissance capabilities of the original tool. The help system is now fully integrated with the tool's functionality and provides users with clear, actionable information.


$ quantumsub quantum -h

Execute quantum reconnaissance scan

USAGE:
    quantumsub quantum [OPTIONS] --target <target> | --targets <target_list>

OPTIONS:
    -t, --target <target>          Primary target domain
    -T, --targets <target_list>    File containing list of target domains
    -w, --wordlist <wordlist>      Path to quantum subdomain wordlist [default: quantum_wordlist.txt]
    -j, --threads <threads>        Number of quantum threads [default: 2000]
    -o, --timeout <timeout>        Request timeout in seconds [default: 1]
    -O, --output <output>          Output directory for results [default: quantum_results]
    -A, --ai                       Enable quantum AI analysis module
    -C, --cloud                    Enable cloud infrastructure detection
    -P, --api                      Enable API endpoint discovery
    -V, --vuln                     Enable vulnerability assessment
    -S, --stealth                  Enable stealth mode (rate limiting)
    -X, --tor                      Route traffic through TOR network
    -v, --verbose                  Enable verbose output

QUANTUM SCAN EXAMPLES:
    Basic scan:              quantumsub quantum -t target.com
    Full reconnaissance:     quantumsub quantum -t target.com -A -C -P -V
    Stealth scan:            quantumsub quantum -t target.com -S -X
    Multiple targets:        quantumsub quantum -T targets.txt -w custom_wordlist.txt
