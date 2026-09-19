// Multi-threaded DPI Engine - Fixed Version
// Architecture: Reader -> LB threads -> FP threads -> Output

#include <iostream>
#include <fstream>
#include <thread>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <memory>
#include <chrono>
#include <iomanip>
#include <algorithm>
#include <optional>

#include "pcap_reader.h"
#include "packet_parser.h"
#include "sni_extractor.h"
#include "types.h"

using namespace PacketAnalyzer;
using namespace DPI;

// =============================================================================
// Thread-Safe Queue
// =============================================================================
template<typename T>
class TSQueue {
public:
    TSQueue(size_t max_size = 10000) : max_size_(max_size), shutdown_(false) {}
    
    void push(T item) {
        std::unique_lock<std::mutex> lock(mutex_);
        not_full_.wait(lock, [this] { return queue_.size() < max_size_ || shutdown_; });
        if (shutdown_) return;
        queue_.push(std::move(item));
        not_empty_.notify_one();
    }
    
    std::optional<T> pop(int timeout_ms = 100) {
        std::unique_lock<std::mutex> lock(mutex_);
        if (!not_empty_.wait_for(lock, std::chrono::milliseconds(timeout_ms),
                                  [this] { return !queue_.empty() || shutdown_; })) {
            return std::nullopt;
        }
        if (queue_.empty()) return std::nullopt;
        T item = std::move(queue_.front());
        queue_.pop();
        not_full_.notify_one();
        return item;
    }
    
    void shutdown() {
        std::lock_guard<std::mutex> lock(mutex_);
        shutdown_ = true;
        not_empty_.notify_all();
        not_full_.notify_all();
    }
    
    size_t size() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return queue_.size();
    }
    
    bool is_shutdown() const { return shutdown_; }

private:
    std::queue<T> queue_;
    mutable std::mutex mutex_;
    std::condition_variable not_empty_;
    std::condition_variable not_full_;
    size_t max_size_;
    std::atomic<bool> shutdown_;
};

// =============================================================================
// Packet Job - Contains all packet data (self-contained, no pointers)
// =============================================================================
struct Packet {
    uint32_t id;
    uint32_t ts_sec;
    uint32_t ts_usec;
    FiveTuple tuple;
    std::vector<uint8_t> data;
    uint8_t tcp_flags;
    size_t payload_offset;
    size_t payload_length;
};

// =============================================================================
// Flow Entry
// =============================================================================
struct FlowEntry {
    FiveTuple tuple;
    AppType app_type = AppType::UNKNOWN;
    std::string sni;
    uint64_t packets = 0;
    uint64_t bytes = 0;
    bool blocked = false;
    bool classified = false;
};

// =============================================================================
// Blocking Rules
// =============================================================================
class Rules {
public:
    void blockIP(const std::string& ip) {
        std::lock_guard<std::mutex> lock(mutex_);
        blocked_ips_.insert(parseIP(ip));
        std::cout << "[Rules] Blocked IP: " << ip << "\n";
    }
    
    void blockApp(const std::string& app) {
        std::lock_guard<std::mutex> lock(mutex_);
        for (int i = 0; i < static_cast<int>(AppType::APP_COUNT); i++) {
            if (appTypeToString(static_cast<AppType>(i)) == app) {
                blocked_apps_.insert(static_cast<AppType>(i));
                std::cout << "[Rules] Blocked app: " << app << "\n";
                return;
            }
        }
        std::cerr << "[Rules] Unknown app: " << app << "\n";
    }
    
    void blockDomain(const std::string& domain) {
        std::lock_guard<std::mutex> lock(mutex_);
        blocked_domains_.push_back(domain);
        std::cout << "[Rules] Blocked domain: " << domain << "\n";
    }
    
    bool isBlocked(uint32_t src_ip, AppType app, const std::string& sni) const {
        std::lock_guard<std::mutex> lock(mutex_);
        if (blocked_ips_.count(src_ip)) return true;
        if (blocked_apps_.count(app)) return true;
        for (const auto& dom : blocked_domains_) {
            if (sni.find(dom) != std::string::npos) return true;
        }
        return false;
    }

private:
    static uint32_t parseIP(const std::string& ip) {
        uint32_t result = 0;
        int octet = 0, shift = 0;
        for (char c : ip) {
            if (c == '.') { result |= (octet << shift); shift += 8; octet = 0; }
            else if (c >= '0' && c <= '9') octet = octet * 10 + (c - '0');
        }
        return result | (octet << shift);
    }
    
    mutable std::mutex mutex_;
    std::unordered_set<uint32_t> blocked_ips_;
    std::unordered_set<AppType> blocked_apps_;
    std::vector<std::string> blocked_domains_;
};

// =============================================================================
// Statistics (thread-safe)
// =============================================================================
struct Stats {
    std::atomic<uint64_t> total_packets{0};
    std::atomic<uint64_t> total_bytes{0};
    std::atomic<uint64_t> forwarded{0};
    std::atomic<uint64_t> dropped{0};
    std::atomic<uint64_t> tcp_packets{0};
    std::atomic<uint64_t> udp_packets{0};
    
    // Per-app stats (protected by mutex)
    std::mutex app_mutex;
    std::unordered_map<AppType, uint64_t> app_counts;
    std::unordered_map<std::string, AppType> detected_snis;
    
    void recordApp(AppType app, const std::string& sni) {
        std::lock_guard<std::mutex> lock(app_mutex);
        app_counts[app]++;
        if (!sni.empty()) {
            detected_snis[sni] = app;
        }
    }
};

// =============================================================================
// Fast Path Processor (one per FP thread)
// =============================================================================
class FastPath {
public:
    FastPath(int id, Rules* rules, Stats* stats, TSQueue<Packet>* output_queue)
        : id_(id), rules_(rules), stats_(stats), output_queue_(output_queue) {}
    
    void setLiveMode(bool live) { live_mode_ = live; }
    
    void start() {
        running_ = true;
        thread_ = std::thread(&FastPath::run, this);
    }
    
    void stop() {
        running_ = false;
        input_queue_.shutdown();
        if (thread_.joinable()) thread_.join();
    }
    
    TSQueue<Packet>& queue() { return input_queue_; }
    
    uint64_t processed() const { return processed_; }
 
private:
    int id_;
    Rules* rules_;
    Stats* stats_;
    TSQueue<Packet>* output_queue_;
    TSQueue<Packet> input_queue_;
    std::unordered_map<FiveTuple, FlowEntry, FiveTupleHash> flows_;
    
    std::atomic<bool> running_{false};
    std::thread thread_;
    std::atomic<uint64_t> processed_{0};
    bool live_mode_ = false;
    
    void run() {
        while (running_) {
            auto pkt_opt = input_queue_.pop(100);
            if (!pkt_opt) continue;
            
            processed_++;
            Packet& pkt = *pkt_opt;
            
            // Get or create flow
            FlowEntry& flow = flows_[pkt.tuple];
            if (flow.packets == 0) {
                flow.tuple = pkt.tuple;
            }
            flow.packets++;
            flow.bytes += pkt.data.size();
            
            // Try to classify if not done yet
            if (!flow.classified) {
                classifyFlow(pkt, flow);
                if (flow.classified) {
                    auto ipToString = [](uint32_t ip) -> std::string {
                        return std::to_string(ip & 0xFF) + "." +
                               std::to_string((ip >> 8) & 0xFF) + "." +
                               std::to_string((ip >> 16) & 0xFF) + "." +
                               std::to_string((ip >> 24) & 0xFF);
                    };
                    if (live_mode_) {
                        std::cout << "{\"type\": \"flow\", \"src_ip\": \"" << ipToString(pkt.tuple.src_ip)
                                  << "\", \"dst_ip\": \"" << ipToString(pkt.tuple.dst_ip)
                                  << "\", \"src_port\": " << pkt.tuple.src_port
                                  << ", \"dst_port\": " << pkt.tuple.dst_port
                                  << ", \"protocol\": " << (int)pkt.tuple.protocol
                                  << ", \"app\": \"" << appTypeToString(flow.app_type)
                                  << "\", \"domain\": \"" << flow.sni << "\"}\n";
                    } else {
                        std::cout << "[DPI_FLOW] " << pkt.tuple.toString() << " | App: " << appTypeToString(flow.app_type) << " | Domain: " << flow.sni << "\n";
                    }
                    std::cout.flush();
                }
            }
            
            // Check blocking
            if (!flow.blocked) {
                bool is_blocked = rules_->isBlocked(pkt.tuple.src_ip, flow.app_type, flow.sni);
                if (is_blocked) {
                    flow.blocked = true;
                    auto ipToString = [](uint32_t ip) -> std::string {
                        return std::to_string(ip & 0xFF) + "." +
                               std::to_string((ip >> 8) & 0xFF) + "." +
                               std::to_string((ip >> 16) & 0xFF) + "." +
                               std::to_string((ip >> 24) & 0xFF);
                    };
                    if (live_mode_) {
                        std::cout << "{\"type\": \"block\", \"ip\": \"" << ipToString(pkt.tuple.src_ip)
                                  << "\", \"reason\": \"C++ rules check (App: " << appTypeToString(flow.app_type)
                                  << " | Domain: " << flow.sni << ")\"}\n";
                    } else {
                        std::cout << "[DPI_BLOCK] Blocked IP: " << ipToString(pkt.tuple.src_ip) 
                                  << " due to " << appTypeToString(flow.app_type) << " / " << flow.sni << "\n";
                    }
                    std::cout.flush();
                }
            }
            
            // Record stats
            stats_->recordApp(flow.app_type, flow.sni);
            
            // Forward or drop
            if (flow.blocked) {
                stats_->dropped++;
            } else {
                stats_->forwarded++;
                if (output_queue_) {
                    output_queue_->push(std::move(pkt));
                }
            }
        }
    }
    
    void classifyFlow(Packet& pkt, FlowEntry& flow) {
        // Try SNI extraction for HTTPS
        if (pkt.tuple.dst_port == 443 && pkt.payload_length > 5) {
            const uint8_t* payload = pkt.data.data() + pkt.payload_offset;
            auto sni = SNIExtractor::extract(payload, pkt.payload_length);
            if (sni) {
                flow.sni = *sni;
                flow.app_type = sniToAppType(*sni);
                flow.classified = true;
                return;
            }
        }
        
        // Try HTTP Host extraction
        if (pkt.tuple.dst_port == 80 && pkt.payload_length > 10) {
            const uint8_t* payload = pkt.data.data() + pkt.payload_offset;
            auto host = HTTPHostExtractor::extract(payload, pkt.payload_length);
            if (host) {
                flow.sni = *host;
                flow.app_type = sniToAppType(*host);
                flow.classified = true;
                return;
            }
        }
        
        // DNS
        if (pkt.tuple.dst_port == 53 || pkt.tuple.src_port == 53) {
            flow.app_type = AppType::DNS;
            flow.classified = true;
            return;
        }
        
        // Port-based fallback (but don't mark as classified - might get SNI later)
        if (pkt.tuple.dst_port == 443) {
            flow.app_type = AppType::HTTPS;
        } else if (pkt.tuple.dst_port == 80) {
            flow.app_type = AppType::HTTP;
        }
    }
};

// =============================================================================
// Load Balancer (one per LB thread)
// =============================================================================
class LoadBalancer {
public:
    LoadBalancer(int id, std::vector<FastPath*> fps)
        : id_(id), fps_(std::move(fps)), num_fps_(fps_.size()) {}
    
    void start() {
        running_ = true;
        thread_ = std::thread(&LoadBalancer::run, this);
    }
    
    void stop() {
        running_ = false;
        input_queue_.shutdown();
        if (thread_.joinable()) thread_.join();
    }
    
    TSQueue<Packet>& queue() { return input_queue_; }
    
    uint64_t dispatched() const { return dispatched_; }

private:
    int id_;
    std::vector<FastPath*> fps_;
    size_t num_fps_;
    TSQueue<Packet> input_queue_;
    
    std::atomic<bool> running_{false};
    std::thread thread_;
    std::atomic<uint64_t> dispatched_{0};
    
    void run() {
        while (running_) {
            auto pkt_opt = input_queue_.pop(100);
            if (!pkt_opt) continue;
            
            // Hash to select FP
            FiveTupleHash hasher;
            size_t fp_idx = hasher(pkt_opt->tuple) % num_fps_;
            
            fps_[fp_idx]->queue().push(std::move(*pkt_opt));
            dispatched_++;
        }
    }
};

// =============================================================================
// DPI Engine
// =============================================================================
class DPIEngine {
public:
    struct Config {
        int num_lbs = 2;
        int fps_per_lb = 2;
    };
    
    DPIEngine(const Config& cfg) : config_(cfg) {
        int total_fps = cfg.num_lbs * cfg.fps_per_lb;
        
        std::cout << "\n";
        std::cout << "╔══════════════════════════════════════════════════════════════╗\n";
        std::cout << "║              DPI ENGINE v2.0 (Multi-threaded)                 ║\n";
        std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
        std::cout << "║ Load Balancers: " << std::setw(2) << cfg.num_lbs 
                  << "    FPs per LB: " << std::setw(2) << cfg.fps_per_lb
                  << "    Total FPs: " << std::setw(2) << total_fps << "     ║\n";
        std::cout << "╚══════════════════════════════════════════════════════════════╝\n\n";
        
        // Create FP threads
        for (int i = 0; i < total_fps; i++) {
            fps_.push_back(std::make_unique<FastPath>(i, &rules_, &stats_, &output_queue_));
        }
        
        // Create LB threads, each managing a subset of FPs
        for (int lb = 0; lb < cfg.num_lbs; lb++) {
            std::vector<FastPath*> lb_fps;
            int start = lb * cfg.fps_per_lb;
            for (int i = 0; i < cfg.fps_per_lb; i++) {
                lb_fps.push_back(fps_[start + i].get());
            }
            lbs_.push_back(std::make_unique<LoadBalancer>(lb, std::move(lb_fps)));
        }
    }
    
    void blockIP(const std::string& ip) { rules_.blockIP(ip); }
    void blockApp(const std::string& app) { rules_.blockApp(app); }
    void blockDomain(const std::string& dom) { rules_.blockDomain(dom); }
    
    bool process(const std::string& input_file, const std::string& output_file, bool live_mode = false) {
        // Open input
        PcapReader reader;
        if (!reader.open(input_file)) return false;
        
        // Open output
        std::ofstream output;
        if (!live_mode) {
            output.open(output_file, std::ios::binary);
            if (!output.is_open()) {
                std::cerr << "Cannot open output file\n";
                return false;
            }
        }
        
        // Write PCAP header
        if (!live_mode) {
            const auto& hdr = reader.getGlobalHeader();
            output.write(reinterpret_cast<const char*>(&hdr), sizeof(hdr));
        }
        
        // Start all threads
        for (auto& fp : fps_) {
            fp->setLiveMode(live_mode);
            fp->start();
        }
        for (auto& lb : lbs_) lb->start();
        
        // Start output writer thread
        std::atomic<bool> output_running{true};
        std::thread output_thread;
        if (!live_mode) {
            output_thread = std::thread([&]() {
                while (output_running || output_queue_.size() > 0) {
                    auto pkt_opt = output_queue_.pop(50);
                    if (!pkt_opt) continue;
                    
                    PcapPacketHeader phdr;
                    phdr.ts_sec = pkt_opt->ts_sec;
                    phdr.ts_usec = pkt_opt->ts_usec;
                    phdr.incl_len = pkt_opt->data.size();
                    phdr.orig_len = pkt_opt->data.size();
                    
                    output.write(reinterpret_cast<const char*>(&phdr), sizeof(phdr));
                    output.write(reinterpret_cast<const char*>(pkt_opt->data.data()), pkt_opt->data.size());
                }
            });
        }
        
        // Read and dispatch packets
        if (!live_mode) {
            std::cout << "[Reader] Processing packets...\n";
        }
        RawPacket raw;
        ParsedPacket parsed;
        uint32_t pkt_id = 0;
        
        while (reader.readNextPacket(raw)) {
            if (!PacketParser::parse(raw, parsed)) continue;
            if (!parsed.has_ip || (!parsed.has_tcp && !parsed.has_udp)) continue;
            
            // Create packet
            Packet pkt;
            pkt.id = pkt_id++;
            pkt.ts_sec = raw.header.ts_sec;
            pkt.ts_usec = raw.header.ts_usec;
            pkt.tcp_flags = parsed.tcp_flags;
            pkt.data = std::move(raw.data);
            
            // Parse 5-tuple
            auto parseIP = [](const std::string& ip) -> uint32_t {
                uint32_t result = 0;
                int octet = 0, shift = 0;
                for (char c : ip) {
                    if (c == '.') { result |= (octet << shift); shift += 8; octet = 0; }
                    else if (c >= '0' && c <= '9') octet = octet * 10 + (c - '0');
                }
                return result | (octet << shift);
            };
            
            pkt.tuple.src_ip = parseIP(parsed.src_ip);
            pkt.tuple.dst_ip = parseIP(parsed.dest_ip);
            pkt.tuple.src_port = parsed.src_port;
            pkt.tuple.dst_port = parsed.dest_port;
            pkt.tuple.protocol = parsed.protocol;
            
            // Calculate payload offset
            pkt.payload_offset = 14;  // Ethernet
            if (pkt.data.size() > 14) {
                uint8_t ip_ihl = pkt.data[14] & 0x0F;
                pkt.payload_offset += ip_ihl * 4;
                
                if (parsed.has_tcp && pkt.payload_offset + 12 < pkt.data.size()) {
                    uint8_t tcp_off = (pkt.data[pkt.payload_offset + 12] >> 4) & 0x0F;
                    pkt.payload_offset += tcp_off * 4;
                } else if (parsed.has_udp) {
                    pkt.payload_offset += 8;
                }
                
                if (pkt.payload_offset < pkt.data.size()) {
                    pkt.payload_length = pkt.data.size() - pkt.payload_offset;
                } else {
                    pkt.payload_length = 0;
                }
            }
            
            // Update stats
            stats_.total_packets++;
            stats_.total_bytes += pkt.data.size();
            if (parsed.has_tcp) stats_.tcp_packets++;
            else if (parsed.has_udp) stats_.udp_packets++;
            
            // Dispatch to LB (hash-based)
            FiveTupleHash hasher;
            size_t lb_idx = hasher(pkt.tuple) % lbs_.size();
            lbs_[lb_idx]->queue().push(std::move(pkt));
        }
        
        if (!live_mode) {
            std::cout << "[Reader] Done reading " << pkt_id << " packets\n";
        }
        reader.close();
        
        // Wait for queues to drain
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        
        // Stop all threads
        for (auto& lb : lbs_) lb->stop();
        for (auto& fp : fps_) fp->stop();
        
        if (!live_mode) {
            output_running = false;
            output_queue_.shutdown();
            output_thread.join();
            output.close();
            // Print report
            printReport();
        }
        
        return true;
    }

private:
    Config config_;
    Rules rules_;
    Stats stats_;
    TSQueue<Packet> output_queue_;
    std::vector<std::unique_ptr<FastPath>> fps_;
    std::vector<std::unique_ptr<LoadBalancer>> lbs_;
    
    void printReport() {
        std::cout << "\n";
        std::cout << "╔══════════════════════════════════════════════════════════════╗\n";
        std::cout << "║                      PROCESSING REPORT                        ║\n";
        std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
        std::cout << "║ Total Packets:      " << std::setw(12) << stats_.total_packets.load() << "                           ║\n";
        std::cout << "║ Total Bytes:        " << std::setw(12) << stats_.total_bytes.load() << "                           ║\n";
        std::cout << "║ TCP Packets:        " << std::setw(12) << stats_.tcp_packets.load() << "                           ║\n";
        std::cout << "║ UDP Packets:        " << std::setw(12) << stats_.udp_packets.load() << "                           ║\n";
        std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
        std::cout << "║ Forwarded:          " << std::setw(12) << stats_.forwarded.load() << "                           ║\n";
        std::cout << "║ Dropped:            " << std::setw(12) << stats_.dropped.load() << "                           ║\n";
        
        // Thread stats
        std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
        std::cout << "║ THREAD STATISTICS                                             ║\n";
        for (size_t i = 0; i < lbs_.size(); i++) {
            std::cout << "║   LB" << i << " dispatched:   " << std::setw(12) << lbs_[i]->dispatched() << "                           ║\n";
        }
        for (size_t i = 0; i < fps_.size(); i++) {
            std::cout << "║   FP" << i << " processed:    " << std::setw(12) << fps_[i]->processed() << "                           ║\n";
        }
        
        // App distribution
        std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
        std::cout << "║                   APPLICATION BREAKDOWN                       ║\n";
        std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
        
        std::lock_guard<std::mutex> lock(stats_.app_mutex);
        
        std::vector<std::pair<AppType, uint64_t>> sorted_apps(
            stats_.app_counts.begin(), stats_.app_counts.end());
        std::sort(sorted_apps.begin(), sorted_apps.end(),
                  [](const auto& a, const auto& b) { return a.second > b.second; });
        
        uint64_t total = stats_.total_packets.load();
        for (const auto& [app, count] : sorted_apps) {
            double pct = total > 0 ? (100.0 * count / total) : 0;
            int bar = static_cast<int>(pct / 5);
            std::string bar_str(bar, '#');
            
            std::cout << "║ " << std::setw(15) << std::left << appTypeToString(app)
                      << std::setw(8) << std::right << count
                      << " " << std::setw(5) << std::fixed << std::setprecision(1) << pct << "% "
                      << std::setw(20) << std::left << bar_str << "  ║\n";
        }
        
        std::cout << "╚══════════════════════════════════════════════════════════════╝\n";
        
        // Detected SNIs
        if (!stats_.detected_snis.empty()) {
            std::cout << "\n[Detected Domains/SNIs]\n";
            for (const auto& [sni, app] : stats_.detected_snis) {
                std::cout << "  - " << sni << " -> " << appTypeToString(app) << "\n";
            }
        }
    }
};

// =============================================================================
// Deep Forensic Analysis (Priority 2)
// =============================================================================

#include <sstream>
#include <iomanip>
#include <fstream>
#include <algorithm>

namespace PacketAnalyzer {

struct HTTPDetails {
    std::string method;
    std::string path;
    std::string host;
};

// Convert a payload segment to a hex and printable ASCII preview
std::string getPayloadPreview(const uint8_t* payload, size_t length, size_t limit = 32) {
    if (length == 0 || !payload) return "No payload";
    std::stringstream ss;
    size_t display_len = std::min(length, limit);
    
    // Hex representation
    ss << "Hex: ";
    for (size_t i = 0; i < display_len; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)payload[i] << " ";
    }
    if (length > limit) ss << "...";
    
    // ASCII representation
    ss << " | ASCII: ";
    for (size_t i = 0; i < display_len; i++) {
        char c = payload[i];
        if (c == '"') {
            ss << "\\\"";
        } else if (c == '\\') {
            ss << "\\\\";
        } else if (c >= 32 && c <= 126) {
            ss << c;
        } else {
            ss << ".";
        }
    }
    if (length > limit) ss << "...";
    
    return ss.str();
}

// Parse cipher suites from TLS Client Hello payload
std::vector<std::string> parseCipherSuites(const uint8_t* payload, size_t length) {
    std::vector<std::string> suites;
    if (length < 43) return suites;
    
    size_t offset = 5; // Skip record header
    offset += 4;       // Skip handshake header
    offset += 2;       // Skip client version
    offset += 32;      // Skip random
    
    if (offset >= length) return suites;
    uint8_t session_id_len = payload[offset];
    offset += 1 + session_id_len;
    
    if (offset + 2 > length) return suites;
    uint16_t cipher_len = (payload[offset] << 8) | payload[offset+1];
    offset += 2;
    
    if (offset + cipher_len > length) return suites;
    for (size_t i = 0; i < cipher_len; i += 2) {
        if (offset + i + 1 >= length) break;
        uint16_t suite = (payload[offset + i] << 8) | payload[offset + i + 1];
        std::stringstream ss;
        ss << "0x" << std::hex << std::setw(4) << std::setfill('0') << suite;
        suites.push_back(ss.str());
    }
    return suites;
}

// Translate TLS version bytes to string
std::string getTLSVersionString(uint16_t version) {
    switch (version) {
        case 0x0301: return "TLS 1.0";
        case 0x0302: return "TLS 1.1";
        case 0x0303: return "TLS 1.2";
        case 0x0304: return "TLS 1.3";
        default: {
            std::stringstream ss;
            ss << "0x" << std::hex << version;
            return ss.str();
        }
    }
}

std::optional<HTTPDetails> extractHTTPDetails(const uint8_t* payload, size_t length) {
    if (length < 10) return std::nullopt;
    
    std::string payload_str(reinterpret_cast<const char*>(payload), std::min(length, (size_t)512));
    size_t first_space = payload_str.find(' ');
    if (first_space == std::string::npos || first_space > 8) return std::nullopt;
    
    std::string method = payload_str.substr(0, first_space);
    if (method != "GET" && method != "POST" && method != "PUT" && method != "DELETE" && 
        method != "HEAD" && method != "OPTIONS" && method != "PATCH") {
        return std::nullopt;
    }
    
    size_t second_space = payload_str.find(' ', first_space + 1);
    if (second_space == std::string::npos) return std::nullopt;
    
    std::string path = payload_str.substr(first_space + 1, second_space - (first_space + 1));
    
    std::string host = "";
    size_t host_idx = payload_str.find("Host: ");
    if (host_idx == std::string::npos) {
        host_idx = payload_str.find("host: ");
    }
    if (host_idx != std::string::npos) {
        size_t start = host_idx + 6;
        size_t end = payload_str.find("\r\n", start);
        if (end != std::string::npos) {
            host = payload_str.substr(start, end - start);
        }
    }
    
    HTTPDetails details;
    details.method = method;
    details.path = path;
    details.host = host;
    return details;
}

std::string ip2String(uint32_t ip) {
    return std::to_string(ip & 0xFF) + "." +
           std::to_string((ip >> 8) & 0xFF) + "." +
           std::to_string((ip >> 16) & 0xFF) + "." +
           std::to_string((ip >> 24) & 0xFF);
}

// Perform deep forensic analysis
bool analyzePcap(const std::string& input_file, const std::string& output_file, Rules& rules) {
    PcapReader reader;
    if (!reader.open(input_file)) {
        std::cerr << "{\"error\": \"Could not open pcap file " << input_file << "\"}\n";
        return false;
    }
    
    uint64_t total_packets = 0;
    uint64_t total_bytes = 0;
    double start_time = 0.0;
    double end_time = 0.0;
    uint64_t tcp_packets = 0;
    uint64_t udp_packets = 0;
    
    struct TimelineEvent {
        uint32_t packet_idx;
        double ts;
        double gap_ms;
        std::string info;
    };
    
    struct FlowAnalysis {
        FiveTuple tuple;
        AppType app_type = AppType::UNKNOWN;
        std::string sni = "";
        bool classified = false;
        bool blocked = false;
        std::string block_reason = "";
        uint64_t packets = 0;
        uint64_t bytes = 0;
        double start_ts = 0.0;
        double end_ts = 0.0;
        
        bool is_tls = false;
        std::string tls_version = "";
        std::vector<std::string> cipher_suites;
        
        bool is_http = false;
        std::string http_method = "";
        std::string http_path = "";
        std::string http_host = "";
        
        bool is_dns = false;
        std::string dns_query = "";
        
        std::vector<TimelineEvent> timeline;
    };
    
    std::vector<std::pair<FiveTuple, FlowAnalysis>> flow_records;
    auto findFlow = [&](const FiveTuple& tpl) -> FlowAnalysis* {
        for (auto& item : flow_records) {
            if (item.first == tpl) return &item.second;
        }
        return nullptr;
    };
    
    struct PacketRecord {
        uint32_t idx;
        double ts;
        std::string src_ip;
        std::string dst_ip;
        uint16_t src_port;
        uint16_t dst_port;
        std::string proto;
        size_t length;
        std::string info;
        std::string payload_preview;
    };
    std::vector<PacketRecord> packet_records;
    
    RawPacket raw;
    ParsedPacket parsed;
    uint32_t pkt_idx = 0;
    
    while (reader.readNextPacket(raw)) {
        if (!PacketParser::parse(raw, parsed)) continue;
        if (!parsed.has_ip || (!parsed.has_tcp && !parsed.has_udp)) continue;
        
        double ts = (double)raw.header.ts_sec + ((double)raw.header.ts_usec / 1000000.0);
        if (total_packets == 0) {
            start_time = ts;
        }
        end_time = ts;
        total_packets++;
        total_bytes += raw.data.size();
        
        if (parsed.has_tcp) tcp_packets++;
        else if (parsed.has_udp) udp_packets++;
        
        auto parseIP = [](const std::string& ip) -> uint32_t {
            uint32_t result = 0;
            int octet = 0, shift = 0;
            for (char c : ip) {
                if (c == '.') { result |= (octet << shift); shift += 8; octet = 0; }
                else if (c >= '0' && c <= '9') octet = octet * 10 + (c - '0');
            }
            return result | (octet << shift);
        };
        
        FiveTuple tuple;
        tuple.src_ip = parseIP(parsed.src_ip);
        tuple.dst_ip = parseIP(parsed.dest_ip);
        tuple.src_port = parsed.src_port;
        tuple.dst_port = parsed.dest_port;
        tuple.protocol = parsed.protocol;
        
        size_t payload_offset = 14;
        uint8_t ip_ihl = raw.data[14] & 0x0F;
        payload_offset += ip_ihl * 4;
        if (parsed.has_tcp && payload_offset + 12 < raw.data.size()) {
            uint8_t tcp_off = (raw.data[payload_offset + 12] >> 4) & 0x0F;
            payload_offset += tcp_off * 4;
        } else if (parsed.has_udp) {
            payload_offset += 8;
        }
        
        const uint8_t* payload_ptr = nullptr;
        size_t payload_len = 0;
        if (payload_offset < raw.data.size()) {
            payload_ptr = raw.data.data() + payload_offset;
            payload_len = raw.data.size() - payload_offset;
        }
        
        FlowAnalysis* flw_ptr = findFlow(tuple);
        if (!flw_ptr) {
            FlowAnalysis new_flw;
            new_flw.tuple = tuple;
            new_flw.start_ts = ts;
            flow_records.push_back({tuple, new_flw});
            flw_ptr = &flow_records.back().second;
        }
        
        FlowAnalysis& flow = *flw_ptr;
        flow.packets++;
        flow.bytes += raw.data.size();
        flow.end_ts = ts;
        
        std::stringstream info_ss;
        if (parsed.has_tcp) {
            info_ss << "TCP [";
            std::vector<std::string> flags;
            if (parsed.tcp_flags & 0x02) flags.push_back("SYN");
            if (parsed.tcp_flags & 0x10) flags.push_back("ACK");
            if (parsed.tcp_flags & 0x01) flags.push_back("FIN");
            if (parsed.tcp_flags & 0x04) flags.push_back("RST");
            if (parsed.tcp_flags & 0x08) flags.push_back("PSH");
            
            for (size_t f = 0; f < flags.size(); f++) {
                info_ss << flags[f] << (f + 1 < flags.size() ? "," : "");
            }
            info_ss << "]";
            
            size_t ip_start = 14;
            size_t tcp_start = ip_start + (raw.data[ip_start] & 0x0F) * 4;
            if (tcp_start + 8 <= raw.data.size()) {
                uint32_t seq = (raw.data[tcp_start + 4] << 24) | (raw.data[tcp_start + 5] << 16) |
                               (raw.data[tcp_start + 6] << 8) | raw.data[tcp_start + 7];
                info_ss << " Seq=" << seq;
            }
        } else {
            info_ss << "UDP";
        }
        
        if (parsed.has_tcp && payload_ptr && SNIExtractor::isTLSClientHello(payload_ptr, payload_len)) {
            flow.is_tls = true;
            auto sni_opt = SNIExtractor::extract(payload_ptr, payload_len);
            if (sni_opt) {
                flow.sni = *sni_opt;
                flow.app_type = AppType::HTTPS;
                flow.classified = true;
            }
            if (payload_len >= 5) {
                uint16_t rec_version = (payload_ptr[1] << 8) | payload_ptr[2];
                flow.tls_version = getTLSVersionString(rec_version);
                flow.cipher_suites = parseCipherSuites(payload_ptr, payload_len);
            }
        }
        else if (parsed.has_tcp && payload_ptr && HTTPHostExtractor::isHTTPRequest(payload_ptr, payload_len)) {
            auto http_opt = extractHTTPDetails(payload_ptr, payload_len);
            if (http_opt) {
                flow.is_http = true;
                flow.http_method = http_opt->method;
                flow.http_path = http_opt->path;
                flow.http_host = http_opt->host;
                flow.sni = http_opt->host;
                flow.app_type = AppType::HTTP;
                flow.classified = true;
            }
        }
        else if (parsed.has_udp && payload_ptr && DNSExtractor::isDNSQuery(payload_ptr, payload_len)) {
            auto query_opt = DNSExtractor::extractQuery(payload_ptr, payload_len);
            if (query_opt) {
                flow.is_dns = true;
                flow.dns_query = *query_opt;
                flow.sni = *query_opt;
                flow.app_type = AppType::DNS;
                flow.classified = true;
            }
        }
        
        if (!flow.classified) {
            if (tuple.dst_port == 443 || tuple.src_port == 443) {
                flow.app_type = AppType::HTTPS;
            } else if (tuple.dst_port == 80 || tuple.src_port == 80) {
                flow.app_type = AppType::HTTP;
            } else if (tuple.dst_port == 53 || tuple.src_port == 53) {
                flow.app_type = AppType::DNS;
            }
        }
        
        if (!flow.blocked) {
            bool blocked = rules.isBlocked(tuple.src_ip, flow.app_type, flow.sni);
            if (blocked) {
                flow.blocked = true;
                std::stringstream block_ss;
                block_ss << "Rule match on IP/App/Domain: " << appTypeToString(flow.app_type);
                if (!flow.sni.empty()) block_ss << " (" << flow.sni << ")";
                flow.block_reason = block_ss.str();
            }
        }
        
        double gap_ms = 0.0;
        if (flow.timeline.size() > 0) {
            gap_ms = (ts - flow.timeline.back().ts) * 1000.0;
        }
        TimelineEvent ev;
        ev.packet_idx = pkt_idx;
        ev.ts = ts;
        ev.gap_ms = gap_ms;
        ev.info = info_ss.str();
        flow.timeline.push_back(ev);
        
        PacketRecord record;
        record.idx = pkt_idx++;
        record.ts = ts;
        record.src_ip = parsed.src_ip;
        record.dst_ip = parsed.dest_ip;
        record.src_port = parsed.src_port;
        record.dst_port = parsed.dest_port;
        record.proto = parsed.has_tcp ? "TCP" : "UDP";
        record.length = raw.data.size();
        record.info = info_ss.str();
        record.payload_preview = getPayloadPreview(payload_ptr, payload_len);
        packet_records.push_back(record);
    }
    
    std::stringstream json;
    json << "{\n";
    
    double total_duration = total_packets > 0 ? (end_time - start_time) : 0.0;
    json << "  \"summary\": {\n";
    json << "    \"total_packets\": " << total_packets << ",\n";
    json << "    \"total_bytes\": " << total_bytes << ",\n";
    json << "    \"duration_sec\": " << total_duration << ",\n";
    json << "    \"tcp_packets\": " << tcp_packets << ",\n";
    json << "    \"udp_packets\": " << udp_packets << "\n";
    json << "  },\n";
    
    json << "  \"flows\": [\n";
    for (size_t f = 0; f < flow_records.size(); f++) {
        const auto& flw = flow_records[f].second;
        json << "    {\n";
        json << "      \"flow_id\": \"" << ip2String(flw.tuple.src_ip) << ":" << flw.tuple.src_port 
             << " -> " << ip2String(flw.tuple.dst_ip) << ":" << flw.tuple.dst_port 
             << " (" << (flw.tuple.protocol == 6 ? "TCP" : "UDP") << ")\",\n";
        json << "      \"src_ip\": \"" << ip2String(flw.tuple.src_ip) << "\",\n";
        json << "      \"dst_ip\": \"" << ip2String(flw.tuple.dst_ip) << "\",\n";
        json << "      \"src_port\": " << flw.tuple.src_port << ",\n";
        json << "      \"dst_port\": " << flw.tuple.dst_port << ",\n";
        json << "      \"protocol\": \"" << (flw.tuple.protocol == 6 ? "TCP" : "UDP") << "\",\n";
        json << "      \"app\": \"" << appTypeToString(flw.app_type) << "\",\n";
        json << "      \"domain\": \"" << flw.sni << "\",\n";
        json << "      \"blocked\": " << (flw.blocked ? "true" : "false") << ",\n";
        json << "      \"block_reason\": \"" << flw.block_reason << "\",\n";
        json << "      \"packet_count\": " << flw.packets << ",\n";
        json << "      \"byte_count\": " << flw.bytes << ",\n";
        json << "      \"duration_sec\": " << (flw.end_ts - flw.start_ts) << ",\n";
        
        if (flw.is_tls) {
            json << "      \"tls\": {\n";
            json << "        \"version\": \"" << flw.tls_version << "\",\n";
            json << "        \"sni\": \"" << flw.sni << "\",\n";
            json << "        \"cipher_suites\": [";
            for (size_t c = 0; c < flw.cipher_suites.size(); c++) {
                json << "\"" << flw.cipher_suites[c] << "\"" << (c + 1 < flw.cipher_suites.size() ? ", " : "");
            }
            json << "]\n";
            json << "      },\n";
        } else {
            json << "      \"tls\": null,\n";
        }
        
        if (flw.is_http) {
            json << "      \"http\": {\n";
            json << "        \"method\": \"" << flw.http_method << "\",\n";
            std::string escaped_path = flw.http_path;
            size_t pos = 0;
            while ((pos = escaped_path.find('"', pos)) != std::string::npos) {
                escaped_path.replace(pos, 1, "\\\"");
                pos += 2;
            }
            json << "        \"path\": \"" << escaped_path << "\",\n";
            json << "        \"host\": \"" << flw.http_host << "\"\n";
            json << "      },\n";
        } else {
            json << "      \"http\": null,\n";
        }
        
        if (flw.is_dns) {
            json << "      \"dns\": {\n";
            json << "        \"query\": \"" << flw.dns_query << "\"\n";
            json << "      },\n";
        } else {
            json << "      \"dns\": null,\n";
        }
        
        json << "      \"timeline\": [\n";
        for (size_t t = 0; t < flw.timeline.size(); t++) {
            const auto& event = flw.timeline[t];
            json << "        {\n";
            json << "          \"packet_idx\": " << event.packet_idx << ",\n";
            json << "          \"ts\": " << std::fixed << std::setprecision(6) << event.ts << ",\n";
            json << "          \"gap_ms\": " << event.gap_ms << ",\n";
            json << "          \"info\": \"" << event.info << "\"\n";
            json << "        }" << (t + 1 < flw.timeline.size() ? ",\n" : "\n");
        }
        json << "      ]\n";
        
        json << "    }" << (f + 1 < flow_records.size() ? ",\n" : "\n");
    }
    json << "  ],\n";
    
    json << "  \"packets\": [\n";
    for (size_t p = 0; p < packet_records.size(); p++) {
        const auto& record = packet_records[p];
        json << "    {\n";
        json << "      \"idx\": " << record.idx << ",\n";
        json << "      \"ts\": " << std::fixed << std::setprecision(6) << record.ts << ",\n";
        json << "      \"src\": \"" << record.src_ip << ":" << record.src_port << "\",\n";
        json << "      \"dst\": \"" << record.dst_ip << ":" << record.dst_port << "\",\n";
        json << "      \"proto\": \"" << record.proto << "\",\n";
        json << "      \"length\": " << record.length << ",\n";
        json << "      \"info\": \"" << record.info << "\",\n";
        std::string esc_preview = record.payload_preview;
        size_t pos = 0;
        while ((pos = esc_preview.find('"', pos)) != std::string::npos) {
            esc_preview.replace(pos, 1, "\\\"");
            pos += 2;
        }
        json << "      \"payload_preview\": \"" << esc_preview << "\"\n";
        json << "    }" << (p + 1 < packet_records.size() ? ",\n" : "\n");
    }
    json << "  ]\n";
    json << "}\n";
    
    if (output_file == "-" || output_file.empty()) {
        std::cout << json.str();
        std::cout.flush();
    } else {
        std::ofstream out(output_file);
        if (out.is_open()) {
            out << json.str();
            out.close();
        } else {
            std::cerr << "Could not write JSON report to " << output_file << "\n";
            return false;
        }
    }
    
    return true;
}

} // namespace PacketAnalyzer

// =============================================================================
// Main
// =============================================================================
void printUsage(const char* prog) {
    std::cout << R"(
DPI Engine v2.0 - Multi-threaded Deep Packet Inspection & Forensic Analyzer
===========================================================================

Usage: )" << prog << R"( <input.pcap> <output.pcap> [options]
       )" << prog << R"( --live [options]
       )" << prog << R"( --analyze <incident.pcap> [output.json] [options]

Options:
  --live               Enable persistent pipe IPC mode reading pcap stream from stdin
  --analyze            Deep forensic analysis of an incident pcap file to JSON output
  --block-ip <ip>      Add IP to blocked rules
  --block-app <app>    Add App name to blocked rules
  --block-domain <dom> Add Domain (regex/substring) to blocked rules
  --lbs <num>          Number of load balancer threads
  --fps <num>          Number of fast path processor threads per LB
)";
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printUsage(argv[0]);
        return 1;
    }
    
    std::string arg1 = argv[1];
    
    // 1. Analyze Mode (Priority 2)
    if (arg1 == "--analyze") {
        if (argc < 3) {
            std::cerr << "Usage: " << argv[0] << " --analyze <incident.pcap> [output.json] [options]\n";
            return 1;
        }
        std::string input_pcap = argv[2];
        std::string output_json = "-";
        int start_options = 3;
        if (argc >= 4 && argv[3][0] != '-') {
            output_json = argv[3];
            start_options = 4;
        }
        
        std::vector<std::string> block_ips, block_apps, block_domains;
        for (int i = start_options; i < argc; i++) {
            std::string arg = argv[i];
            if (arg == "--block-ip" && i + 1 < argc) block_ips.push_back(argv[++i]);
            else if (arg == "--block-app" && i + 1 < argc) block_apps.push_back(argv[++i]);
            else if (arg == "--block-domain" && i + 1 < argc) block_domains.push_back(argv[++i]);
        }
        
        Rules rules;
        for (const auto& ip : block_ips) rules.blockIP(ip);
        for (const auto& app : block_apps) rules.blockApp(app);
        for (const auto& dom : block_domains) rules.blockDomain(dom);
        
        if (!PacketAnalyzer::analyzePcap(input_pcap, output_json, rules)) {
            return 1;
        }
        return 0;
    }
    
    // 2. Live Mode or Standard Mode
    bool live_mode = false;
    std::string input = "";
    std::string output = "";
    int option_start = 3;
    
    if (arg1 == "--live") {
        live_mode = true;
        input = "-";
        output = "-";
        option_start = 2;
    } else {
        if (argc < 3) {
            printUsage(argv[0]);
            return 1;
        }
        input = argv[1];
        output = argv[2];
        option_start = 3;
    }
    
    DPIEngine::Config cfg;
    std::vector<std::string> block_ips, block_apps, block_domains;
    
    for (int i = option_start; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--block-ip" && i + 1 < argc) block_ips.push_back(argv[++i]);
        else if (arg == "--block-app" && i + 1 < argc) block_apps.push_back(argv[++i]);
        else if (arg == "--block-domain" && i + 1 < argc) block_domains.push_back(argv[++i]);
        else if (arg == "--lbs" && i + 1 < argc) cfg.num_lbs = std::stoi(argv[++i]);
        else if (arg == "--fps" && i + 1 < argc) cfg.fps_per_lb = std::stoi(argv[++i]);
    }
    
    DPIEngine engine(cfg);
    
    for (const auto& ip : block_ips) engine.blockIP(ip);
    for (const auto& app : block_apps) engine.blockApp(app);
    for (const auto& dom : block_domains) engine.blockDomain(dom);
    
    if (!engine.process(input, output, live_mode)) {
        return 1;
    }
    
    if (!live_mode) {
        std::cout << "\nOutput written to: " << output << "\n";
    }
    return 0;
}
