Fast, multithreaded TCP port scanner script with service detection and HTML reporting.
Usage:
python scanner.py [host] [options]

-p, --ports: Port range (e.g., 1-1024) [default: 1-65535]

-t, --threads: Number of threads [default: 16]

-o, --output: Output file (.txt or .html)

```
# Scan common ports
python scanner.py example.com -p 1-1024

# Scan with more threads
python scanner.py example.com -t 32

# Save results to HTML
python scanner.py example.com -o report.html
```
