#pragma once
#include "types.hpp"
#include <filesystem>
#include <string>
#include <unordered_set>

namespace sentinel {
struct RuleDecision { Verdict verdict{Verdict::Allow}; std::string reason{"No blocking rule matched"}; };
class RuleEngine {
 public:
  void load(const std::filesystem::path& path);
  RuleDecision decide(const ParsedPacket& packet) const;
  size_t count() const;
 private:
  std::unordered_set<std::string> blocked_domains_, allowed_domains_, blocked_apps_;
  std::unordered_set<uint32_t> blocked_ips_;
};
}
