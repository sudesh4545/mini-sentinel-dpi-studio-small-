# SentinelDPI — Deep Packet Inspection Studio

SentinelDPI is an original, privacy-first C++20 portfolio project by **Sudesh Mehar**. It analyzes saved Ethernet PCAP files offline, groups packets into bidirectional flows, extracts limited protocol metadata, applies transparent filtering rules, writes a filtered capture, and generates JSON/CSV reports for a TypeScript dashboard.

> Defensive and educational scope: this project never captures live traffic, decrypts TLS, stores payloads in reports, steals credentials, or uploads packet data. Analyze only captures you own or are authorized to inspect.

## What the video teaches

The referenced video presents DPI as a stronger systems project than a typical clone application. Its main pipeline is: PCAP reader → protocol parser → five-tuple connection tracker → TLS SNI/application classification → rule decision → filtered PCAP and statistics. It also explains why consistent hashing keeps packets from one flow on the same worker, and how load-balancer, fast-path, output and thread-safe queue components can scale processing.

SentinelDPI independently implements that product idea with a simpler auditable worker-pool design and additional privacy/reporting features. No source code was copied from the reference repository.

## Features

- Dependency-free PCAP reader and writer for classic Ethernet captures
- Bounds-checked Ethernet, IPv4, TCP and UDP parsing
- Canonical bidirectional five-tuple flow tracking
- Metadata inspectors for TLS ClientHello SNI, HTTP `Host`, and DNS query names
- Explainable allow/drop rule engine for domains, applications and IPs
- Allow-list precedence and exact/subdomain-aware domain matching
- Parallel packet processing with configurable C++ worker threads
- Original packet ordering in the filtered output capture
- Privacy-first reports with `/24` IP anonymization enabled by default
- JSON and CSV reports without packet payload content
- Dark responsive TypeScript report dashboard that works fully offline
- AXIOM AI report copilot with a private server-side OpenAI integration and offline fallback
- Deterministic synthetic PCAP generator and CTest unit tests

## Architecture

```text
                       ┌────────────────────┐
input.pcap ───────────▶│ validated reader   │
                       └─────────┬──────────┘
                                 │ packet index
                   ┌─────────────┼─────────────┐
                   ▼             ▼             ▼
              worker 0      worker 1      worker N
              parse          parse          parse
              inspect        inspect        inspect
              classify       classify       classify
              decide         decide         decide
                   └─────────────┬─────────────┘
                                 ▼
                    flow table + ordered verdicts
                       ┌─────────┴──────────┐
                       ▼                    ▼
                 filtered.pcap      report.json / flows.csv
                                             │
                                             ▼
                                    offline web dashboard
```

## Build and test

Requirements: CMake 3.20+ and a C++20 compiler.

```powershell
cmake -S . -B build -G "MinGW Makefiles"
cmake --build build
ctest --test-dir build --output-on-failure
```

Generate a safe sample and run the engine:

```powershell
python tools/generate_sample_pcap.py sample.pcap
./build/sentinel-dpi.exe --input sample.pcap --output filtered.pcap `
  --rules config/rules.conf --threads 4 --json report.json --csv flows.csv
```

The default JSON/CSV reports mask the final IP octet. Use `--show-ips` only on authorized lab data when exact addresses are truly needed.

## Rule file

Rules use one `key=value` pair per line:

```ini
allow_domain=github.com
block_domain=ads.example.test
block_app=netflix
block_ip=203.0.113.99
```

An allow-domain rule wins before blocking rules. Domain matching accepts the exact domain and its subdomains, not arbitrary unsafe substring matches.

## Dashboard

Compile once with `npx tsc -p dashboard/tsconfig.json`, serve the `dashboard` folder locally, then load `report.json`. All parsing and visualization remain in the browser; the report is not uploaded.

To run the dashboard with AXIOM AI, install dashboard dependencies, keep the API key in a server environment variable, and start its local server:

```powershell
cd dashboard
npm install
$env:OPENAI_API_KEY="your-key"
npm start
```

Without a key, AXIOM automatically provides a limited offline summary, drop explanation and rule-suggestion mode. The online integration sends summarized flow metadata only—not raw PCAP bytes or packet payloads—and requests `store: false`.

For a completely free local model with no API key, install Ollama and download the default lightweight model:

```powershell
ollama pull qwen3:1.7b
npm start
```

AXIOM automatically prefers this local model, falls back to OpenAI when `OPENAI_API_KEY` is configured, and otherwise keeps its built-in offline analyst available.

Alternatively, create a Groq free-tier key, copy `dashboard/.env.example` to `dashboard/.env`, and set `GROQ_API_KEY`. AXIOM's provider order is local Ollama → Groq → OpenAI → offline analyst. Secrets are never included in browser JavaScript or report files.

## Known boundaries

- Classic PCAP only; PCAP-NG is intentionally rejected.
- Ethernet + IPv4 are supported in version 1. IPv6 is a planned extension.
- SNI is visible only when present in a classic TLS ClientHello. Encrypted Client Hello cannot be classified this way.
- TCP reassembly is not included yet, so metadata split across packets may remain unknown.
- This is a portfolio/learning engine, not an inline production firewall.

## Roadmap

- PCAP-NG and IPv6 readers
- TCP stream reassembly with strict memory limits
- YAML/JSON rules with validation
- Per-worker flow ownership via consistent hashing
- Application signatures and confidence scores
- Benchmark fixtures, fuzz tests and performance budgets

## Author

Built by **Sudesh Mehar** — [GitHub](https://github.com/sudesh4545) · [LinkedIn](https://www.linkedin.com/in/sudeshmehar3/) · [Portfolio](https://sudesh4545.github.io/sudesh-portfolio/) · [Email](mailto:sudeshmehar3@gmail.com)
