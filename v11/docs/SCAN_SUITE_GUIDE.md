# CYESCO Exposure Scan Suite

This module checks a target for common open ports, HTTP security headers, and TLS details, then saves the result to `logs/reports/` as Markdown, log, and JSON files.

## How to use

1. Open **Exposure Scan** from the sidebar.
2. Enter a domain, IP, or URL.
3. Run the scan.
4. Review:
   - open ports
   - HTTP/HTTPS header findings
   - TLS details
   - saved report filenames

## Why it matters

The AI advisor reads the saved JSON reports back from `logs/reports/`, so every new scan improves the next recommendation pass.
