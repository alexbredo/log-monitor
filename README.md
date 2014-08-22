log-monitor
===========

Monitor all log appends to a file and creates custom events (Example: Save to Elasticsearch)

Features:
 * TELNET with simple NT OS
 * Catch actions

Dependencies:
 * watchdog
 * pathtools
 * My site-packages(3) --> common-modules

Usage:
```bash
# Generate Config
python log-reader.py -d config.xml
# Run
python log-reader.py
```

TODO: 
 * Integrate Generic Syslog Parser
 * cleanup
 
Contribution welcome.

All rights reserved.
(c) 2014 by Alexander Bredo