#pragma once
#include "pcap.hpp"
#include "rules.hpp"
#include <filesystem>
#include <mutex>
#include <unordered_map>

namespace sentinel {
struct EngineOptions { size_t workers{4}; bool anonymize_report{true}; };
struct EngineStats { uint64_t total{}, parsed{}, forwarded{}, dropped{}, bytes{}; double elapsed_ms{}; };
class DpiEngine {
 public:
  DpiEngine(RuleEngine rules, EngineOptions options);
  EngineStats process(const std::filesystem::path& input, const std::filesystem::path& output);
  void write_json_report(const std::filesystem::path& path) const;
  void write_csv_report(const std::filesystem::path& path) const;
  const std::vector<FlowSummary>& flows() const { return flow_snapshot_; }
 private:
  RuleEngine rules_; EngineOptions options_; EngineStats stats_{};
  std::unordered_map<FlowKey,FlowSummary,FlowKeyHash> flows_; std::vector<FlowSummary> flow_snapshot_;
  mutable std::mutex mutex_;
};
}
