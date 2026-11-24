# flokbn Configuration Examples

This directory contains example configuration files for the flokbn threat detection system.

## Overview

flokbn uses various filtering mechanisms to identify and block malicious traffic:

1. **IP-based ban control** - Whitelist/blacklist specific IP addresses and CIDR ranges in the jail/ban pipeline (analysis output is not filtered by these lists)
2. **User-Agent filtering** - Whitelist/blacklist based on exact User-Agent strings
3. **Clustering analysis** - Detect threat patterns through IP clustering
4. **Jail system** - Persistent ban management

## File Structure

```
config_examples/
├── README.md             # This file
├── complex-static.toml   # Runnable full-coverage static-mode example config
├── whitelist.txt         # IP addresses/CIDRs to never ban
├── blacklist.txt         # IP addresses/CIDRs to always ban
├── ua_whitelist.txt      # Exact User-Agent strings that whitelist IPs
└── ua_blacklist.txt      # Exact User-Agent strings that blacklist IPs
```

## Configuration Files

### complex-static.toml
A runnable static-mode configuration exercising the full filter surface:
global IP/UA lists, per-trie User-Agent/endpoint/time filters, CIDR-range
analysis, multiple cluster parameter sets per trie, and jail wiring. This is
the reference copy; the easiest way to run it is to unpack a self-contained,
ready-to-run demo (this config, a matching 1,000,000-line synthetic log, and
all four list files) with `flokbn generate static-demo --out ./demo`, then
`flokbn static --config ./demo/complex-static.toml --plain`. See the
"Complex Static Analysis" guide in the documentation for a full walkthrough.

### whitelist.txt
Contains IP addresses and CIDR ranges that should **never** be banned. These
ranges are protected from jail/ban only - their traffic still appears in
analysis results and statistics:
- Internal networks (192.168.0.0/16, 10.0.0.0/8)
- Essential services (DNS servers, CDNs)
- Monitoring and health check services
- Known legitimate sources

### blacklist.txt
Contains IP addresses and CIDR ranges that should **always** be banned:
- Known malicious networks
- Spam and bot networks
- Tor exit nodes (if desired)
- Geolocation-based blocks
- Custom manual blocks

### ua_whitelist.txt
Contains exact User-Agent strings that **whitelist** the source IP:
- Search engine crawlers (Googlebot, Bingbot)
- SEO and analysis tools (AhrefsBot, SemrushBot)
- Monitoring services (UptimeRobot, Pingdom)
- Internal tools and services
- Legitimate security scanners

**Security warning:** the User-Agent header is chosen by the client and is
trivially spoofed. One request carrying a listed string makes its source IP
immune: it is excluded from detection, removed from active bans, and removed
from the manual IP blacklist (`blacklist.txt`). Use this list to reduce false
positives, not as access control. For crawlers and monitoring services you
must never ban, put their published IP ranges in `whitelist.txt` instead, and
do not ship ordinary browser strings (the example file contains some for
illustration only).

### ua_blacklist.txt
Contains exact User-Agent strings that **blacklist** the source IP:
- Security testing tools (sqlmap, nmap, nikto)
- Web scraping frameworks (scrapy, selenium)
- Command line tools (curl, wget)
- Attack tools and frameworks
- Brute force and dictionary tools

## Usage

### In Configuration File
Reference these files in your `flokbn.toml` configuration:

```toml
[global]
whitelist = "config_examples/whitelist.txt"
blacklist = "config_examples/blacklist.txt"
userAgentWhitelist = "config_examples/ua_whitelist.txt"
userAgentBlacklist = "config_examples/ua_blacklist.txt"
```

Note: relative paths are resolved from the directory you run flokbn in (the
current working directory), not from the config file location.

### File Format
All four files share these rules:
- One entry per line
- A line whose first non-blank character is `#` is a comment
- Empty lines are ignored
- Leading and trailing whitespace is trimmed

They differ in how a `#` **after** an entry is read - see below.

#### IP Files Format (whitelist.txt, blacklist.txt)
**IPv4 only** - each line is a CIDR or a bare IPv4 address; a bare address is
a single host and is treated as `/32`. A malformed entry or an IPv6 line
aborts the run at startup, naming the line number and file (IPv4-only tool).
The same rules apply to per-trie `cidrRanges` entries in the config and to
`--rangesCidr`.

A `#` after an entry starts an inline comment (a CIDR never contains `#`):
```
# Comment
192.168.1.0/24    # Internal network
10.0.0.1          # Specific IP, same as 10.0.0.1/32
```

#### User-Agent Files Format (ua_whitelist.txt, ua_blacklist.txt)
Entries are **exact** User-Agent strings - the full User-Agent header must
match the line completely. They are NOT substrings and NOT regexes.

Only a **leading** `#` starts a comment. A `#` inside a line is part of the
entry, because real User-Agent strings contain it - so do not append a
comment to an entry, it would become part of the string to match:
```
# Comment
Googlebot/2.1 (+http://www.google.com/bot.html)
curl/7.68.0
sqlmap/1.7.2#stable (http://sqlmap.org)
```
`Googlebot` alone would only match requests whose entire User-Agent header
is literally `Googlebot`.

The User-Agent files need a `%u` field in the `logFormat` of the mode being
run (`[static] logFormat` or `[live] logFormat`; both defaults have one); a
configured User-Agent list with a format that has no `%u` aborts the run.

## Processing Order

flokbn processes filtering in this order:

1. **Parse log entries** using configured log format
2. **Apply time and regex filters** from trie configuration
3. **Check User-Agent whitelist** - exclude matching IPs from analysis
4. **Check User-Agent blacklist** - mark matching IPs for immediate banning
5. **Perform clustering analysis** on remaining IPs
6. **Apply IP whitelist** - drop detected ranges fully covered by a single whitelist entry before the jail, and subtract the whitelist from the published ban file (whitelisted traffic still appears in the analysis output)
7. **Update jail file** with new detections
8. **Generate ban file** with active bans + IP blacklist

## Customization

### For Your Environment
1. **Review and modify** the example entries
2. **Add your specific networks** to whitelist.txt
3. **Add known threats** to blacklist.txt
4. **Customize User-Agent entries** for your application
5. **Test thoroughly** before production deployment

### Best Practices
1. **Start conservative** - use restrictive patterns initially
2. **Monitor false positives** - adjust patterns based on results
3. **Regular updates** - keep threat intelligence current
4. **Document changes** - maintain notes about custom entries
5. **Backup configurations** - version control your customizations

## Security Considerations

### Whitelist Security
- Keep whitelist minimal and specific
- Regularly review for outdated entries
- Monitor for abuse of whitelisted ranges
- Use specific CIDRs rather than broad ranges

### Blacklist Security
- Verify entries before adding to blacklist
- Consider impact on legitimate traffic
- Use threat intelligence sources
- Monitor for false positives

### User-Agent Security
- Remember matches are exact: one version bump in a User-Agent string
  (e.g. `curl/8.4.0` -> `curl/8.5.0`) means the entry no longer matches
- List every variant you want to match explicitly
- Some entries may match legitimate tools
- Balance security with usability

## Troubleshooting

### Common Issues
1. **File not found** - Check file paths and permissions
2. **Invalid CIDR format** - Verify the entry is an IPv4 CIDR (e.g.,
   192.168.1.0/24) or a bare IPv4 address. IPv4 only: an IPv6 line aborts the
   run at startup (IPv4-only tool)
3. **UA entry never matches** - Entries are exact strings; check for missing
   version suffixes, extra whitespace, or a comment appended after a `#` (in
   User-Agent files that text is part of the entry)
4. **Performance issues** - Consider file size and pattern complexity

### Debugging Tips
1. **Check log output** for parsing errors
2. **Test with small datasets** first
3. **Use plain text output** for debugging
4. **Validate file formats** manually
5. **Monitor system resources** during operation

## Examples

### Basic Setup
Minimal configuration for testing:
```toml
[global]
whitelist = "config_examples/whitelist.txt"
blacklist = "config_examples/blacklist.txt"
```

### Advanced Setup
Full configuration with User-Agent filtering:
```toml
[global]
whitelist = "config_examples/whitelist.txt"
blacklist = "config_examples/blacklist.txt"
userAgentWhitelist = "config_examples/ua_whitelist.txt"
userAgentBlacklist = "config_examples/ua_blacklist.txt"
```

### Production Deployment
1. Copy example files to your deployment location
2. Customize entries for your environment
3. Test with non-production data
4. Monitor for false positives
5. Deploy gradually with monitoring

## Support

For questions and issues:
1. Check the main flokbn documentation
2. Review log output for error messages
3. Test configurations with sample data
4. Validate file formats and permissions
5. Monitor system resources during operation
