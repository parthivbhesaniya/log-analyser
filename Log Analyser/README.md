# Log Analyser

A high-performance log analysis project built in C++ with an optional HTML dashboard and HTTP server.

## Features

- Supports multiple log formats with automatic detection:
  - Nginx/Apache combined access logs
  - HDFS DataNode / NameSystem logs
  - Syslog (BSD-style)
  - JSON-per-line logs
- Processes files using memory-mapped I/O for speed and large-file support
- Zero-copy parsing to minimize heap allocations
- Aggregates metrics including:
  - total requests and bytes transferred
  - status code distribution
  - top IP addresses and endpoints
  - request rates per hour
  - method breakdown
  - latency percentiles (p50, p95, p99)
  - error rate
- Produces JSON output for dashboard integration

## Repository Contents

- `log_analyzer.cpp` — main analyzer implementation
- `server.py` — lightweight Python HTTP server for the dashboard
- `dashboard.html` — dashboard UI for uploading logs and viewing results
- `generate_logs.cpp` — test log generator for synthetic Nginx-style logs
- `serve.sh` — simple shell command to start a static file server

## Requirements

- C++17-compatible compiler (g++, clang++)
- Python 3 (for the dashboard server)

## Build

Compile the analyzer:

```bash
cd "/Log Analyser"
g++ -O2 -std=c++17 -o log_analyzer log_analyzer.cpp
```

Compile the log generator (optional):

```bash
g++ -O2 -std=c++17 -o generate_logs generate_logs.cpp
```

## Usage

Analyze a log file and print output to the console:

```bash
./log_analyzer server.log
```

Analyze a log file and write JSON output to a report:

```bash
./log_analyzer server.log report.json
```

## Dashboard

Start the dashboard server:

```bash
python3 server.py --port 8080
```

Then open:

```text
http://localhost:8080/dashboard.html
```

Upload a log file through the dashboard to run the analyzer and view the JSON report.

## Generate Test Logs

Create a synthetic Nginx-style access log for testing:

```bash
./generate_logs 100000 example.log
```

## Notes

- `serve.sh` launches a basic static HTTP server on port 8080, but it does not run the analyzer backend.
- `server.py` requires the compiled `log_analyzer` binary to be present in the same directory.


