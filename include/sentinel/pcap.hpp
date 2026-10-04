#pragma once
#include "types.hpp"
#include <filesystem>
#include <fstream>
#include <vector>

namespace sentinel {
class PcapReader {
 public:
  explicit PcapReader(const std::filesystem::path& path);
  std::vector<PacketRecord> read_all();
  bool swapped() const { return swapped_; }
 private:
  std::ifstream input_; bool swapped_{}; uint32_t snaplen_{}; uint32_t network_{};
};
class PcapWriter {
 public:
  explicit PcapWriter(const std::filesystem::path& path);
  void write(const PacketRecord& packet);
 private: std::ofstream output_;
};
}
