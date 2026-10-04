#pragma once
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace sentinel {
struct PacketRecord { uint32_t ts_sec{}; uint32_t ts_usec{}; uint32_t original_length{}; std::vector<uint8_t> bytes; };
struct Endpoint { uint32_t ip{}; uint16_t port{}; auto operator<=>(const Endpoint&) const = default; };
struct FlowKey {
  Endpoint first{}, second{}; uint8_t protocol{};
  auto operator<=>(const FlowKey&) const = default;
};
struct FlowKeyHash { size_t operator()(const FlowKey& key) const noexcept; };
enum class Protocol : uint8_t { Unknown=0, ICMP=1, TCP=6, UDP=17 };
enum class Verdict { Allow, Drop };
struct ParsedPacket {
  bool valid{}; uint32_t source_ip{}, destination_ip{}; uint16_t source_port{}, destination_port{};
  Protocol protocol{Protocol::Unknown}; size_t payload_offset{}, payload_length{}; std::string host; std::string application{"Unknown"};
};
struct FlowSummary { FlowKey key{}; uint64_t packets{}, bytes{}; Verdict verdict{Verdict::Allow}; std::string host; std::string application{"Unknown"}; std::string reason; };
std::string ip_to_string(uint32_t ip);
FlowKey canonical_flow(const ParsedPacket& packet);
}
