#pragma once
#include "types.hpp"
#include <span>

namespace sentinel {
class PacketParser {
 public:
  static ParsedPacket parse(const PacketRecord& packet);
  static std::string extract_tls_sni(std::span<const uint8_t> payload);
  static std::string extract_http_host(std::span<const uint8_t> payload);
  static std::string extract_dns_name(std::span<const uint8_t> payload);
  static std::string classify(std::string_view host, uint16_t port, Protocol protocol);
};
}
