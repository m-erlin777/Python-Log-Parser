# Python-Log-Parser
Python script that parses Linux authentication logs to detect failed and successful SSH login attempts.
Extracts username, IP address, and raw log entry for each match, making it useful for security monitoring, auditing and troubleshooting.

## Features
- Detects failed SSH login attempts (including invalid user attempts)
- Detects successful SSH login attempts
- Outputs structured results for further analysis
- Supports custom log file paths

## Function
Log File Reading:
- Script reads specified log file line-by-line, avoiding high memory usage with large log files.

Pattern Matching:
- *Failed logins* are detected using regex, capturing IP addresses and usernames from failed authentication attempts
- *Successful logins* are detected using a separate regex, capturing successful SSH connections

Data Structuring:
- (`timestamp`) Data and time of event
- (`user`) Username involved
- (`ip`) Source IP address

JSON Output:
- After parsing, script prints results in JSON:
### Example Output:
```
  {
       "failed_logins": [
           {"timestamp": "Jan  1 12:00:00", "user": "root", "ip": "192.168.1.10"}
       ],
       "successful_logins": [
           {"timestamp": "Jan  1 12:05:00", "user": "admin", "ip": "192.168.1.15"}
       ]
   }
```

![Example Output](https://i.imgur.com/mS7bjuY.png)
