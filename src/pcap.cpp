#include "sentinel/pcap.hpp"
#include <array>
#include <bit>
#include <cstring>
#include <stdexcept>

namespace sentinel {
namespace { uint32_t swap32(uint32_t v){return((v&0x000000ffu)<<24)|((v&0x0000ff00u)<<8)|((v&0x00ff0000u)>>8)|((v&0xff000000u)>>24);} uint16_t swap16(uint16_t v){return uint16_t((v<<8)|(v>>8));} template<class T>T read(std::istream& s){T v{};s.read(reinterpret_cast<char*>(&v),sizeof(v));return v;} }
PcapReader::PcapReader(const std::filesystem::path& path):input_(path,std::ios::binary){
  if(!input_) throw std::runtime_error("Cannot open input PCAP: "+path.string());
  const uint32_t magic=read<uint32_t>(input_); if(magic==0xd4c3b2a1) swapped_=true; else if(magic!=0xa1b2c3d4) throw std::runtime_error("Unsupported PCAP magic number");
  uint16_t major=read<uint16_t>(input_),minor=read<uint16_t>(input_); if(swapped_){major=swap16(major);minor=swap16(minor);} if(major!=2||minor!=4) throw std::runtime_error("Unsupported PCAP version");
  input_.ignore(8); snaplen_=read<uint32_t>(input_); network_=read<uint32_t>(input_); if(swapped_){snaplen_=swap32(snaplen_);network_=swap32(network_);} if(network_!=1) throw std::runtime_error("Only Ethernet PCAP captures are supported");
}
std::vector<PacketRecord>PcapReader::read_all(){std::vector<PacketRecord> out;while(input_.peek()!=EOF){PacketRecord p;p.ts_sec=read<uint32_t>(input_);p.ts_usec=read<uint32_t>(input_);uint32_t incl=read<uint32_t>(input_);p.original_length=read<uint32_t>(input_);if(!input_)break;if(swapped_){p.ts_sec=swap32(p.ts_sec);p.ts_usec=swap32(p.ts_usec);incl=swap32(incl);p.original_length=swap32(p.original_length);}if(incl>snaplen_||incl>16*1024*1024)throw std::runtime_error("Invalid packet length");p.bytes.resize(incl);input_.read(reinterpret_cast<char*>(p.bytes.data()),incl);if(!input_)throw std::runtime_error("Truncated PCAP packet");out.push_back(std::move(p));}return out;}
PcapWriter::PcapWriter(const std::filesystem::path& path):output_(path,std::ios::binary){if(!output_)throw std::runtime_error("Cannot create output PCAP");const uint32_t magic=0xa1b2c3d4;const uint16_t major=2,minor=4;const int32_t zone=0;const uint32_t sig=0,snap=65535,network=1;output_.write((char*)&magic,4);output_.write((char*)&major,2);output_.write((char*)&minor,2);output_.write((char*)&zone,4);output_.write((char*)&sig,4);output_.write((char*)&snap,4);output_.write((char*)&network,4);}
void PcapWriter::write(const PacketRecord&p){uint32_t incl=(uint32_t)p.bytes.size();output_.write((char*)&p.ts_sec,4);output_.write((char*)&p.ts_usec,4);output_.write((char*)&incl,4);output_.write((char*)&p.original_length,4);output_.write((char*)p.bytes.data(),incl);}
}
