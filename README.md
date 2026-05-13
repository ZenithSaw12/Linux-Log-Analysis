# Linux Log File Analysis, Automation, and SIEM Visualization

### Manual Log Analysis

> <img src="images/1log.png" alt="Sample Logs" width="60%">

> <img src="images/2sheets.png" alt="Findings" width="60%">

#### Summary

The logs reveal multiple authentication failures originating from external sources, specifically 218.188.2.4 and 220.135.151.1. A significant cluster of failed attempts occurred on June 15 at 2:04:59, rapidly targeting the root account from the host 220-135-151-1.hinet-ip.hinet.net. This pattern is a clear indicator of a brute-force attack attempting to gain administrative access.

Additionally, the IP address 218.188.2.4 repeatedly triggered "Unknown user" failures, suggesting that attackers are probing the system by testing various non-existent usernames. On the local side, while standard user sessions for "cyrus" and "news" were opened and closed, a logrotate Alert error was recorded at 4:06:20. This indicates a potential system maintenance issue or misconfiguration that requires further investigation alongside the external security threats.


### Automating Log Analysis

> python
```python

print
```
