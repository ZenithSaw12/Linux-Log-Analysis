# Linux Log File Analysis, Automation, and SIEM Visualization

### Manual Log Analysis

<div align="center">
  <img src="images/1log.png" alt="Sample Logs" width="70%">
  <br>
  <i>Log File Snippet</i>
</div>

<br>

<div align="center">
    <img src="images/2sheets.png" alt="Findings" width="60%">
    <br>
    <i>Some Suspicious Event Logged on Google Sheets</i>
    
</div>

#### Summary

The logs reveal multiple authentication failures originating from external sources, specifically **218.188.2.4** and **220.135.151.1**. A significant cluster of failed attempts occurred on June 15 at 2:04:59, rapidly targeting the root account from the host 220-135-151-1.hinet-ip.hinet.net. This pattern is a clear indicator of a brute-force attack attempting to gain administrative access.

Additionally, the IP address 218.188.2.4 repeatedly triggered "Unknown user" failures, suggesting that attackers are probing the system by testing various non-existent usernames. On the local side, while standard user sessions for "cyrus" and "news" were opened and closed, a logrotate Alert error was recorded at 4:06:20. This indicates a potential system maintenance issue or misconfiguration that requires further investigation alongside the external security threats.


### Automating Log Analysis

> python
```python

# log_analysis.py
# Step 1: Open and read log file
with open("Linux_2k.log", "r", encoding="utf-8") as file:
    logs = file.readlines() #reads each line and returns list 

# Step 2: Focus on lines 200–500
subset_logs = logs[199:500] # Python is 0-based index

# Step 3: Search for suspicious patterns
suspicious_entries = []
for line in subset_logs:
    if "Failed password" in line:
        suspicious_entries.append(("Failed Login", line.strip()))
    elif "authentication failure" in line:
        suspicious_entries.append(("Auth Failure", line.strip()))
    elif "user unknown" in line or "invalid user" in line:
        suspicious_entries.append(("Unknown User", line.strip()))

# Step 4: Print Results
print("=== Suspicious Log Entries (Lines 200–500) ===")
for entry_type, entry in suspicious_entries:
    print(f"[{entry_type}] {entry}")

print(f"\nTotal suspicious entries found:{len(suspicious_entries)}")
```

This python script opens the Linux_2k.log file and reads each line, appending it to a list called `logs`. From `logs`, it takes lines 200 to 500 and puts them into a subset list called `subset_logs`. We use a for loop to interate through each line in `subset_logs` to check for keywords such as "Failed password", "authentication failure", "user unkown", and "invalid user". Any matching line is added to the list `suspicious_entries` with a tag for the event type (e.g. Auth Failure). The script prints flagged entires and shows the total number of suspicious entries discovered. Scanning log lines is automated so that suspicious activity is quickly identified, otherwise needing manual review.


#### Running The Script

<div align="center">
    <img src="images/3output.png" alt="Output" width="80%">
    <br>
    <i>Output To Terminal Snippet</i>
    
</div>

<br>

We can export the script as a csv and open in Excel or Sheets

> python
```python

# Step 5: Save results to a CSV file
import csv

with open("suspicious_logs.csv", "w", newline="") as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(["Type", "Log Entry"])
    writer.writerows(suspicious_entries)
print("Results saved to suspicious_logs.csv")

```

<br>

## Log Analysis and Visualization with Splunk

### Searching and Filtering Suspicious Activity

Query for suspicious authentication activity

> splunk
> ```spl
> source="Linux2k.log" host="ZenithS" sourcetype="Linux" ("Failedpassword" OR "authentication failure" OR "invalid user" OR "user unknown")
> ```

This filters the log to match the usual indicators of a brute-force attempts or unauthorized access.

This includes:

- Repeated failed logins
- Invalid or unknown users
- Authentication failures

<br>

<div align="center">
    <img src="images/4splunk.png" alt="Splunk Output" width="90%">
    <br>
    <i>Output</i>
</div>

<br>

Running the query, we notice that one entry stands out:

- Repeated failed login attempts
- Same username attempted: root
- Same source IP: 207.243.167.114
- Attempts occur a few seconds apart

_These are telltale signs of a brute-force login attempt_

### Pattern Analysis

Confirming repetitive behaviour

Now switching to the **Patterns** tab

<div align="center">
    <img src="images/5patterns.png" alt="Splunk Patterns Tab" width="60%">
    <br>
    <i>Patterns Tab</i>
</div>

<br>

The data confirms that several source IPs generated repeated authentication failures against the same target account. This consistent, repetitive pattern demonstrates that the activity is a systematic attack rather than a random occurrence.

#### Statisitics View

<div align="center">
    <img src="images/6statistics.png" alt="Statistics View" width="60%">
    <br>
    <i>Grouping events with split rows and filters (Highest 10 rhost by count)</i>
</div>

<br>

Notice:

- 150.183.249.110 has the highest number of event count
- Targeted username is consistently root
- Other IPs show fewer and scattered attempts

### Visualization View: Presenting the Attack Timeline

<div align="center">
    <img src="images/7linechart.png" alt="Linechart Visualization" width="60%">
    <br>
    <i>Linechart</i>
</div>

<br>

**Observations from the Line Chart**

- There are sharp spikes in authentication failures that occur within very short timeframes.
- A large number of these attempts are specifically directed at the root account.
- These peaks in activity align with repeated login failures coming from the same source IP addresses.

**What This Suggests**

- The bursty timing of these events indicates that attackers are using automated brute-force attempts
- The persistent focus on the root username confirms a clear intent to gain full administrative control over the system.
- This specific pattern is a classic sign of botnets or automated scanning tools being used to probe for weaknesses.
