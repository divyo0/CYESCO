# Honeypot Guide

The honeypot is a single control-and-check tool. Use it like this:

1. Open **Honeypot Control**.
2. Click **Start honeypot**.
3. Click **Run self-test**.
4. From another authorized device on the same network, connect to one of the listening ports:
   - 2222 SSH
   - 2121 FTP
   - 2323 Telnet
   - 8081 Web
5. Confirm that:
   - the status changes to RUNNING
   - self-test returns working listeners
   - recent connections appear
   - `logs/honeypot_log.txt` contains entries

If the self-test says `ALL WORKING`, the honeypot listeners are responding correctly.
