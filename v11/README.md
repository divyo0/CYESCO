# CYESCO - Advance Network Analyser Tool

Created by Team DM.

This project keeps the original toolkit intact and layers a polished web dashboard on top of it. The UI now includes live charts, a refresh button, theme and accent selectors, clearer module cards, report history, AI insights, and a single honeypot control + checker panel.

## Included modules

- WiFi Network Analyzer
- Packet Sniffer & Mini IDS
- Multi-threaded Port Scanner + Banner Grabber
- Firewall Rule Analyzer
- Honeypot System
- OSINT + Geolocation
- Endpoint Security Helper
- DNS / TLS Audit
- Live System Health Monitor
- AI Security Advisor
- Incident Report Builder
- Honeypot control and self-test panel

## Run

```bash
pip install -r requirements.txt
python run.py
```

The server listens on `0.0.0.0:5000`, so the dashboard can be opened by LAN IP.

## Where reports are saved

Generated reports are written into:

- `logs/reports/*.md`
- `logs/reports/*.log`
- `logs/reports/*.json`

The AI advisor reads those saved outputs again to improve later recommendations.

## Honeypot verification

Open the honeypot control page, start the honeypot, and then connect from another device on your authorized network to one of the listening ports. The self-test panel checks the listeners, and the recent connections list plus `logs/honeypot_log.txt` should show activity. If the self-test says `ALL WORKING`, the listeners are responding correctly.

## Theme controls

Use the theme selector to switch between dark and light mode, and use the accent selector to change the highlight color. The controls are styled for readability in both themes.

## Safety

Use only on systems and networks you own or have permission to test.


## Added in this build

- Exposure Scan Suite
- Better AI report spacing and visibility
- Honeypot usage guide
- Larger presentation assets for viva/demo


## Added to the heavy build

- Extended subdomain wordlist for the OSINT scanner
- Service fingerprint reference database
- CVE readiness notes pack
- Presentation backup deck
- Sample report history data

These additions preserve the original toolkit and make the package larger and more presentation-ready.
