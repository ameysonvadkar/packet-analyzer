#include "dpi_engine.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <cstring>

// UDP socket headers
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>

namespace DPI {

// ============================================================================
// DPIEngine Implementation (v2.0 - LB-free direct dispatch)
// ============================================================================

DPIEngine::DPIEngine(const Config& config)
    : config_(config), output_queue_(10000) {
    
    std::cout << "\n";
    std::cout << "╔══════════════════════════════════════════════════════════════╗\n";
    std::cout << "║              DPI ENGINE v2.0 (Direct Dispatch)              ║\n";
    std::cout << "║               Deep Packet Inspection System                 ║\n";
    std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
    std::cout << "║ Configuration:                                              ║\n";
    std::cout << "║   FastPath threads:  " << std::setw(3) << config.num_fps
              << "                                       ║\n";
    if (config.enable_control) {
        std::cout << "║   Control port:      " << std::setw(5) << config.control_port
                  << "                                     ║\n";
    }
    if (config.enable_stats_stream) {
        std::cout << "║   Stats port:        " << std::setw(5) << config.stats_port
                  << "                                     ║\n";
    }
    std::cout << "╚══════════════════════════════════════════════════════════════╝\n";
}

DPIEngine::~DPIEngine() {
    stop();
}

bool DPIEngine::initialize() {
    // Create rule manager
    rule_manager_ = std::make_unique<RuleManager>();
    
    // Load rules if specified
    if (!config_.rules_file.empty()) {
        rule_manager_->loadRules(config_.rules_file);
    }
    
    // Create output callback
    auto output_cb = [this](const PacketJob& job, PacketAction action) {
        handleOutput(job, action);
    };
    
    // Create FP manager (creates FP threads and their queues)
    // Direct dispatch: Reader -> FP (no LB layer)
    fp_manager_ = std::make_unique<FPManager>(config_.num_fps, rule_manager_.get(), output_cb);
    
    // Create global connection table
    global_conn_table_ = std::make_unique<GlobalConnectionTable>(config_.num_fps);
    for (int i = 0; i < config_.num_fps; i++) {
        global_conn_table_->registerTracker(i, &fp_manager_->getFP(i).getConnectionTracker());
    }
    
    std::cout << "[DPIEngine] Initialized successfully\n";
    return true;
}

void DPIEngine::start() {
    if (running_) return;
    
    running_ = true;
    processing_complete_ = false;
    
    // Start output thread
    output_thread_ = std::thread(&DPIEngine::outputThreadFunc, this);
    
    // Start FP threads
    fp_manager_->startAll();
    
    // Start UDP control thread if enabled
    if (config_.enable_control) {
        control_thread_ = std::thread(&DPIEngine::controlThreadFunc, this);
    }
    
    // Start UDP stats streaming thread if enabled
    if (config_.enable_stats_stream) {
        stats_thread_ = std::thread(&DPIEngine::statsThreadFunc, this);
    }
    
    std::cout << "[DPIEngine] All threads started\n";
}

void DPIEngine::stop() {
    if (!running_) return;
    
    running_ = false;
    
    // Stop FP threads
    if (fp_manager_) {
        fp_manager_->stopAll();
    }
    
    // Stop output thread
    output_queue_.shutdown();
    if (output_thread_.joinable()) {
        output_thread_.join();
    }
    
    // Stop control thread
    if (control_thread_.joinable()) {
        control_thread_.join();
    }
    
    // Stop stats thread
    if (stats_thread_.joinable()) {
        stats_thread_.join();
    }
    
    std::cout << "[DPIEngine] All threads stopped\n";
}

void DPIEngine::waitForCompletion() {
    // Wait for reader to finish
    if (reader_thread_.joinable()) {
        reader_thread_.join();
    }
    
    // Wait a bit for queues to drain
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    // Signal completion
    processing_complete_ = true;
}

bool DPIEngine::processFile(const std::string& input_file,
                            const std::string& output_file) {
    
    std::cout << "\n[DPIEngine] Processing: " << input_file << "\n";
    std::cout << "[DPIEngine] Output to:  " << output_file << "\n\n";
    
    // Initialize if not already done
    if (!rule_manager_) {
        if (!initialize()) {
            return false;
        }
    }
    
    // Open output file
    output_file_.open(output_file, std::ios::binary);
    if (!output_file_.is_open()) {
        std::cerr << "[DPIEngine] Error: Cannot open output file\n";
        return false;
    }
    
    // Start processing threads
    start();
    
    // Start reader thread
    reader_thread_ = std::thread(&DPIEngine::readerThreadFunc, this, input_file);
    
    // Wait for completion
    waitForCompletion();
    
    // Give some time for final packets to process
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    
    // Stop all threads
    stop();
    
    // Close output file
    if (output_file_.is_open()) {
        output_file_.close();
    }
    
    // Print final report
    std::cout << generateReport();
    std::cout << fp_manager_->generateClassificationReport();
    
    return true;
}

void DPIEngine::readerThreadFunc(const std::string& input_file) {
    PacketAnalyzer::PcapReader reader;
    
    if (!reader.open(input_file)) {
        std::cerr << "[Reader] Error: Cannot open input file\n";
        return;
    }
    
    // Write PCAP header to output
    writeOutputHeader(reader.getGlobalHeader());
    
    PacketAnalyzer::RawPacket raw;
    PacketAnalyzer::ParsedPacket parsed;
    uint32_t packet_id = 0;
    
    std::cout << "[Reader] Starting packet processing...\n";
    
    int total_fps = config_.num_fps;
    FiveTupleHash hasher;
    
    while (reader.readNextPacket(raw)) {
        // Parse the packet
        if (!PacketAnalyzer::PacketParser::parse(raw, parsed)) {
            continue;  // Skip unparseable packets
        }
        
        // Only process IP packets with TCP/UDP
        if (!parsed.has_ip || (!parsed.has_tcp && !parsed.has_udp)) {
            continue;
        }
        
        // Create packet job
        PacketJob job = createPacketJob(raw, parsed, packet_id++);
        
        // Update global stats
        stats_.total_packets++;
        stats_.total_bytes += job.data.size();
        
        if (parsed.has_tcp) {
            stats_.tcp_packets++;
        } else if (parsed.has_udp) {
            stats_.udp_packets++;
        }
        
        // DIRECT DISPATCH to FP (no LB layer - fixes starvation bug)
        int fp_index = hasher(job.tuple) % total_fps;
        fp_manager_->getFPQueue(fp_index).push(std::move(job));
    }
    
    std::cout << "[Reader] Finished reading " << packet_id << " packets\n";
    reader.close();
}

void DPIEngine::submitPacket(PacketJob&& job) {
    if (!running_) return;
    
    // Update global stats
    stats_.total_packets++;
    stats_.total_bytes += job.data.size();
    
    if (job.tuple.protocol == 6) { // TCP
        stats_.tcp_packets++;
    } else if (job.tuple.protocol == 17) { // UDP
        stats_.udp_packets++;
    }
    
    FiveTupleHash hasher;
    int fp_index = hasher(job.tuple) % config_.num_fps;
    fp_manager_->getFPQueue(fp_index).push(std::move(job));
}

PacketJob DPIEngine::createPacketJob(const PacketAnalyzer::RawPacket& raw,
                                      const PacketAnalyzer::ParsedPacket& parsed,
                                      uint32_t packet_id) {
    PacketJob job;
    job.packet_id = packet_id;
    job.ts_sec = raw.header.ts_sec;
    job.ts_usec = raw.header.ts_usec;
    
    // Set five-tuple - parse IP addresses from string back to uint32
    auto parseIP = [](const std::string& ip) -> uint32_t {
        uint32_t result = 0;
        int octet = 0;
        int shift = 0;
        for (char c : ip) {
            if (c == '.') {
                result |= (octet << shift);
                shift += 8;
                octet = 0;
            } else if (c >= '0' && c <= '9') {
                octet = octet * 10 + (c - '0');
            }
        }
        result |= (octet << shift);
        return result;
    };
    
    job.tuple.src_ip = parseIP(parsed.src_ip);
    job.tuple.dst_ip = parseIP(parsed.dest_ip);
    job.tuple.src_port = parsed.src_port;
    job.tuple.dst_port = parsed.dest_port;
    job.tuple.protocol = parsed.protocol;
    
    // TCP flags
    job.tcp_flags = parsed.tcp_flags;
    
    // Copy packet data
    job.data = raw.data;
    
    // Calculate offsets
    job.eth_offset = 0;
    job.ip_offset = 14;  // Ethernet header is 14 bytes
    
    // IP header length
    if (job.data.size() > 14) {
        uint8_t ip_ihl = job.data[14] & 0x0F;
        size_t ip_header_len = ip_ihl * 4;
        job.transport_offset = 14 + ip_header_len;
        
        // Transport header length
        if (parsed.has_tcp && job.data.size() > job.transport_offset + 12) {
            uint8_t tcp_data_offset = (job.data[job.transport_offset + 12] >> 4) & 0x0F;
            size_t tcp_header_len = tcp_data_offset * 4;
            job.payload_offset = job.transport_offset + tcp_header_len;
        } else if (parsed.has_udp) {
            job.payload_offset = job.transport_offset + 8;  // UDP header is 8 bytes
        }
        
        if (job.payload_offset < job.data.size()) {
            job.payload_length = job.data.size() - job.payload_offset;
            job.payload_data = job.data.data() + job.payload_offset;
        }
    }
    
    return job;
}

void DPIEngine::outputThreadFunc() {
    while (running_ || !output_queue_.empty()) {
        auto job_opt = output_queue_.popWithTimeout(std::chrono::milliseconds(100));
        
        if (job_opt) {
            writeOutputPacket(*job_opt);
        }
    }
}

void DPIEngine::handleOutput(const PacketJob& job, PacketAction action) {
    if (action == PacketAction::DROP) {
        stats_.dropped_packets++;
        return;
    }
    
    stats_.forwarded_packets++;
    output_queue_.push(job);
}

bool DPIEngine::writeOutputHeader(const PacketAnalyzer::PcapGlobalHeader& header) {
    std::lock_guard<std::mutex> lock(output_mutex_);
    
    if (!output_file_.is_open()) return false;
    
    output_file_.write(reinterpret_cast<const char*>(&header), sizeof(header));
    return output_file_.good();
}

void DPIEngine::writeOutputPacket(const PacketJob& job) {
    std::lock_guard<std::mutex> lock(output_mutex_);
    
    if (!output_file_.is_open()) return;
    
    // Write packet header
    PacketAnalyzer::PcapPacketHeader pkt_header;
    pkt_header.ts_sec = job.ts_sec;
    pkt_header.ts_usec = job.ts_usec;
    pkt_header.incl_len = job.data.size();
    pkt_header.orig_len = job.data.size();
    
    output_file_.write(reinterpret_cast<const char*>(&pkt_header), sizeof(pkt_header));
    output_file_.write(reinterpret_cast<const char*>(job.data.data()), job.data.size());
}

// ============================================================================
// UDP Control Thread
// ============================================================================

void DPIEngine::controlThreadFunc() {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        std::cerr << "[Control] Failed to create UDP socket\n";
        return;
    }
    
    // Set non-blocking with timeout
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 200000; // 200ms timeout
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    struct sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(config_.control_port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    
    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        std::cerr << "[Control] Failed to bind to port " << config_.control_port << "\n";
        close(sock);
        return;
    }
    
    std::cout << "[Control] Listening on UDP port " << config_.control_port << "\n";
    
    char buffer[1024];
    while (running_) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        
        ssize_t n = recvfrom(sock, buffer, sizeof(buffer) - 1, 0,
                             (struct sockaddr*)&client_addr, &client_len);
        
        if (n <= 0) continue;
        
        buffer[n] = '\0';
        std::string cmd(buffer);
        
        // Remove trailing newline
        while (!cmd.empty() && (cmd.back() == '\n' || cmd.back() == '\r')) {
            cmd.pop_back();
        }
        
        std::string response;
        
        // Parse command
        if (cmd.rfind("BLOCK_IP ", 0) == 0) {
            std::string ip = cmd.substr(9);
            blockIP(ip);
            response = "OK: Blocked IP " + ip;
        } else if (cmd.rfind("UNBLOCK_IP ", 0) == 0) {
            std::string ip = cmd.substr(11);
            unblockIP(ip);
            response = "OK: Unblocked IP " + ip;
        } else if (cmd.rfind("BLOCK_APP ", 0) == 0) {
            std::string app = cmd.substr(10);
            blockApp(app);
            response = "OK: Blocked app " + app;
        } else if (cmd.rfind("UNBLOCK_APP ", 0) == 0) {
            std::string app = cmd.substr(12);
            unblockApp(app);
            response = "OK: Unblocked app " + app;
        } else if (cmd.rfind("BLOCK_DOMAIN ", 0) == 0) {
            std::string domain = cmd.substr(13);
            blockDomain(domain);
            response = "OK: Blocked domain " + domain;
        } else if (cmd.rfind("UNBLOCK_DOMAIN ", 0) == 0) {
            std::string domain = cmd.substr(15);
            unblockDomain(domain);
            response = "OK: Unblocked domain " + domain;
        } else if (cmd == "STATUS") {
            response = generateJSONStats();
        } else if (cmd == "RULES") {
            auto rule_stats = rule_manager_->getStats();
            response = "IPs:" + std::to_string(rule_stats.blocked_ips) +
                       " Apps:" + std::to_string(rule_stats.blocked_apps) +
                       " Domains:" + std::to_string(rule_stats.blocked_domains);
        } else {
            response = "ERR: Unknown command";
        }
        
        // Send response back
        sendto(sock, response.c_str(), response.size(), 0,
               (struct sockaddr*)&client_addr, client_len);
    }
    
    close(sock);
    std::cout << "[Control] Stopped\n";
}

// ============================================================================
// UDP Stats Streaming Thread
// ============================================================================

void DPIEngine::statsThreadFunc() {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        std::cerr << "[Stats] Failed to create UDP socket\n";
        return;
    }
    
    struct sockaddr_in dest_addr;
    std::memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(config_.stats_port);
    dest_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    
    std::cout << "[Stats] Streaming to UDP port " << config_.stats_port << "\n";
    
    while (running_) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        
        std::string json = generateJSONStats();
        
        sendto(sock, json.c_str(), json.size(), 0,
               (struct sockaddr*)&dest_addr, sizeof(dest_addr));
    }
    
    close(sock);
    std::cout << "[Stats] Stopped\n";
}

// ============================================================================
// Rule Management API
// ============================================================================

void DPIEngine::blockIP(const std::string& ip) {
    if (rule_manager_) {
        rule_manager_->blockIP(ip);
    }
}

void DPIEngine::unblockIP(const std::string& ip) {
    if (rule_manager_) {
        rule_manager_->unblockIP(ip);
    }
}

void DPIEngine::blockApp(AppType app) {
    if (rule_manager_) {
        rule_manager_->blockApp(app);
    }
}

void DPIEngine::blockApp(const std::string& app_name) {
    for (int i = 0; i < static_cast<int>(AppType::APP_COUNT); i++) {
        if (appTypeToString(static_cast<AppType>(i)) == app_name) {
            blockApp(static_cast<AppType>(i));
            return;
        }
    }
    std::cerr << "[DPIEngine] Unknown app: " << app_name << "\n";
}

void DPIEngine::unblockApp(AppType app) {
    if (rule_manager_) {
        rule_manager_->unblockApp(app);
    }
}

void DPIEngine::unblockApp(const std::string& app_name) {
    for (int i = 0; i < static_cast<int>(AppType::APP_COUNT); i++) {
        if (appTypeToString(static_cast<AppType>(i)) == app_name) {
            unblockApp(static_cast<AppType>(i));
            return;
        }
    }
}

void DPIEngine::blockDomain(const std::string& domain) {
    if (rule_manager_) {
        rule_manager_->blockDomain(domain);
    }
}

void DPIEngine::unblockDomain(const std::string& domain) {
    if (rule_manager_) {
        rule_manager_->unblockDomain(domain);
    }
}

bool DPIEngine::loadRules(const std::string& filename) {
    if (rule_manager_) {
        return rule_manager_->loadRules(filename);
    }
    return false;
}

bool DPIEngine::saveRules(const std::string& filename) {
    if (rule_manager_) {
        return rule_manager_->saveRules(filename);
    }
    return false;
}

// ============================================================================
// Reporting
// ============================================================================

std::string DPIEngine::generateJSONStats() const {
    std::ostringstream ss;
    ss << "{";
    ss << "\"total_packets\":" << stats_.total_packets.load();
    ss << ",\"total_bytes\":" << stats_.total_bytes.load();
    ss << ",\"tcp_packets\":" << stats_.tcp_packets.load();
    ss << ",\"udp_packets\":" << stats_.udp_packets.load();
    ss << ",\"forwarded\":" << stats_.forwarded_packets.load();
    ss << ",\"dropped\":" << stats_.dropped_packets.load();
    
    if (fp_manager_) {
        auto fp_stats = fp_manager_->getAggregatedStats();
        ss << ",\"active_connections\":" << fp_stats.total_connections;
        
        // Per-FP stats
        ss << ",\"fp_stats\":[";
        for (int i = 0; i < fp_manager_->getNumFPs(); i++) {
            if (i > 0) ss << ",";
            auto fps = fp_manager_->getFP(i).getStats();
            ss << "{\"id\":" << i
               << ",\"processed\":" << fps.packets_processed
               << ",\"forwarded\":" << fps.packets_forwarded
               << ",\"dropped\":" << fps.packets_dropped
               << ",\"connections\":" << fps.connections_tracked
               << "}";
        }
        ss << "]";
    }
    
    // App distribution
    if (fp_manager_) {
        ss << ",\"apps\":{";
        std::unordered_map<AppType, size_t> app_counts;
        for (int i = 0; i < fp_manager_->getNumFPs(); i++) {
            fp_manager_->getFP(i).getConnectionTracker().forEach([&](const Connection& conn) {
                app_counts[conn.app_type]++;
            });
        }
        bool first = true;
        for (const auto& pair : app_counts) {
            if (!first) ss << ",";
            ss << "\"" << appTypeToString(pair.first) << "\":" << pair.second;
            first = false;
        }
        ss << "}";
        
        // Detected domains
        ss << ",\"domains\":[";
        std::unordered_map<std::string, AppType> domains;
        for (int i = 0; i < fp_manager_->getNumFPs(); i++) {
            fp_manager_->getFP(i).getConnectionTracker().forEach([&](const Connection& conn) {
                if (!conn.sni.empty()) {
                    domains[conn.sni] = conn.app_type;
                }
            });
        }
        first = true;
        for (const auto& pair : domains) {
            if (!first) ss << ",";
            ss << "{\"domain\":\"" << pair.first << "\",\"app\":\""
               << appTypeToString(pair.second) << "\"}";
            first = false;
        }
        ss << "]";
    }
    
    // Rules
    if (rule_manager_) {
        auto rule_stats = rule_manager_->getStats();
        ss << ",\"rules\":{\"blocked_ips\":" << rule_stats.blocked_ips
           << ",\"blocked_apps\":" << rule_stats.blocked_apps
           << ",\"blocked_domains\":" << rule_stats.blocked_domains
           << ",\"blocked_ports\":" << rule_stats.blocked_ports
           << "}";
    }
    
    ss << "}";
    return ss.str();
}

std::string DPIEngine::generateReport() const {
    std::ostringstream ss;
    
    ss << "\n╔══════════════════════════════════════════════════════════════╗\n";
    ss << "║                  DPI ENGINE v2.0 STATISTICS                 ║\n";
    ss << "╠══════════════════════════════════════════════════════════════╣\n";
    
    ss << "║ PACKET STATISTICS                                          ║\n";
    ss << "║   Total Packets:      " << std::setw(12) << stats_.total_packets.load() << "                        ║\n";
    ss << "║   Total Bytes:        " << std::setw(12) << stats_.total_bytes.load() << "                        ║\n";
    ss << "║   TCP Packets:        " << std::setw(12) << stats_.tcp_packets.load() << "                        ║\n";
    ss << "║   UDP Packets:        " << std::setw(12) << stats_.udp_packets.load() << "                        ║\n";
    
    ss << "╠══════════════════════════════════════════════════════════════╣\n";
    ss << "║ FILTERING STATISTICS                                       ║\n";
    ss << "║   Forwarded:          " << std::setw(12) << stats_.forwarded_packets.load() << "                        ║\n";
    ss << "║   Dropped/Blocked:    " << std::setw(12) << stats_.dropped_packets.load() << "                        ║\n";
    
    if (stats_.total_packets > 0) {
        double drop_rate = 100.0 * stats_.dropped_packets.load() / stats_.total_packets.load();
        ss << "║   Drop Rate:          " << std::setw(11) << std::fixed << std::setprecision(2) << drop_rate << "%                       ║\n";
    }
    
    if (fp_manager_) {
        auto fp_stats = fp_manager_->getAggregatedStats();
        ss << "╠══════════════════════════════════════════════════════════════╣\n";
        ss << "║ FAST PATH STATISTICS (Direct Dispatch)                     ║\n";
        ss << "║   FP Processed:       " << std::setw(12) << fp_stats.total_processed << "                        ║\n";
        ss << "║   FP Forwarded:       " << std::setw(12) << fp_stats.total_forwarded << "                        ║\n";
        ss << "║   FP Dropped:         " << std::setw(12) << fp_stats.total_dropped << "                        ║\n";
        ss << "║   Active Connections: " << std::setw(12) << fp_stats.total_connections << "                        ║\n";
        
        // Per-FP breakdown to verify even distribution
        ss << "╠══════════════════════════════════════════════════════════════╣\n";
        ss << "║ PER-FP DISTRIBUTION (verifies even load)                   ║\n";
        for (int i = 0; i < fp_manager_->getNumFPs(); i++) {
            auto fps = fp_manager_->getFP(i).getStats();
            ss << "║   FP" << i << ": " << std::setw(12) << fps.packets_processed
               << " pkts, " << std::setw(8) << fps.connections_tracked << " conns      ║\n";
        }
    }
    
    if (rule_manager_) {
        auto rule_stats = rule_manager_->getStats();
        ss << "╠══════════════════════════════════════════════════════════════╣\n";
        ss << "║ BLOCKING RULES                                             ║\n";
        ss << "║   Blocked IPs:        " << std::setw(12) << rule_stats.blocked_ips << "                        ║\n";
        ss << "║   Blocked Apps:       " << std::setw(12) << rule_stats.blocked_apps << "                        ║\n";
        ss << "║   Blocked Domains:    " << std::setw(12) << rule_stats.blocked_domains << "                        ║\n";
        ss << "║   Blocked Ports:      " << std::setw(12) << rule_stats.blocked_ports << "                        ║\n";
    }
    
    ss << "╚══════════════════════════════════════════════════════════════╝\n";
    
    return ss.str();
}

std::string DPIEngine::generateClassificationReport() const {
    if (fp_manager_) {
        return fp_manager_->generateClassificationReport();
    }
    return "";
}

const DPIStats& DPIEngine::getStats() const {
    return stats_;
}

void DPIEngine::printStatus() const {
    std::cout << "\n--- Live Status ---\n";
    std::cout << "Packets: " << stats_.total_packets.load()
              << " | Forwarded: " << stats_.forwarded_packets.load()
              << " | Dropped: " << stats_.dropped_packets.load() << "\n";
    
    if (fp_manager_) {
        auto fp_stats = fp_manager_->getAggregatedStats();
        std::cout << "Connections: " << fp_stats.total_connections << "\n";
    }
}

} // namespace DPI
