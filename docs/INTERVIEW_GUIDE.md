# SentinelDPI interview guide

## One-line pitch

SentinelDPI is a privacy-first C++ network-analysis pipeline that reads authorized PCAP captures, groups packets into flows, applies explainable security rules, and presents the results in a TypeScript dashboard with an optional AI analyst.

## What to demonstrate

1. Generate the safe synthetic capture with `tools/generate_sample_pcap.py`.
2. Build and run the C++ engine.
3. Show the allow/drop rules in `config/rules.conf`.
4. Load `report.json` in the dashboard.
5. Explain a dropped flow and ask AXIOM AI for a summary.
6. Run CTest to prove the core parser and rule behavior is verified.

## Important engineering decisions

- Canonical five-tuples group both directions of a connection into one flow.
- Bounds checks protect every protocol parser from truncated packet data.
- Parallel workers inspect packets while output is written in original order.
- Reports contain metadata only and anonymize IP addresses by default.
- AI credentials stay on the server and raw packet payloads are never sent to an AI provider.

## Honest boundaries

Version 1 supports classic Ethernet PCAP, IPv4, TCP and UDP. It does not decrypt TLS, capture live traffic, or replace a production firewall. PCAP-NG, IPv6, bounded TCP reassembly and fuzz testing are future extensions.
