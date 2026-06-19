// DPI Daemon - Supports both file processing and live capture
// with UDP control socket and stats streaming for dashboard integration.

#include <iostream>
#include <string>
#include <thread>
#include <signal.h>
#include "dpi_engine.h"
#include "pcap_live_capturer.h"
#include "packet_parser.h"

using namespace DPI;
using namespace PacketAnalyzer;

// Global engine pointer for signal handling
static DPIEngine* g_engine = nullptr;
static LiveCapturer* g_capturer = nullptr;

void signalHandler(int sig) {
    std::cout << "\n[Daemon] Received signal " << sig << ", shutting down...\n";
    if (g_capturer) g_capturer->stopCapture();
    if (g_engine) g_engine->stop();
}

void printUsage(const char* prog) {
    std::cout << R"(
╔══════════════════════════════════════════════════════════════╗
║            DPI DAEMON v2.0 - Dashboard Mode                 ║
║           Deep Packet Inspection with Live Capture           ║
╚══════════════════════════════════════════════════════════════╝

Usage:
  )" << prog << R"( file <input.pcap> <output.pcap> [options]
  )" << prog << R"( live [interface] [options]
  )" << prog << R"( list-interfaces

Modes:
  file              Process a PCAP file
  live              Capture packets live from a network interface
  list-interfaces   List available network interfaces

Options:
  --block-ip <ip>        Block source IP
  --block-app <app>      Block application
  --block-domain <dom>   Block domain
  --rules <file>         Load blocking rules from file
  --fps <n>              Number of FastPath threads (default: 4)
  --control              Enable UDP control socket (port 5005)
  --stats                Enable UDP stats streaming (port 5006)
  --filter <bpf>         BPF filter for live capture (e.g., "tcp port 443")

Examples:
  )" << prog << R"( file capture.pcap filtered.pcap --control --stats
  )" << prog << R"( live en0 --control --stats --block-app YouTube
  )" << prog << R"( live --control --stats
  )" << prog << R"( list-interfaces
)";
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printUsage(argv[0]);
        return 1;
    }
    
    std::string mode = argv[1];
    
    // ============================================================
    // List interfaces mode
    // ============================================================
    if (mode == "list-interfaces") {
        auto interfaces = LiveCapturer::listInterfaces();
        if (interfaces.empty()) {
            std::cout << "No interfaces found (libpcap may not be available)\n";
        } else {
            std::cout << "Available network interfaces:\n";
            for (const auto& iface : interfaces) {
                std::cout << "  - " << iface << "\n";
            }
            std::cout << "\nDefault: " << LiveCapturer::getDefaultInterface() << "\n";
        }
        return 0;
    }
    
    // Parse common options
    DPIEngine::Config config;
    config.num_fps = 4;
    config.enable_control = false;
    config.enable_stats_stream = false;
    
    std::vector<std::string> block_ips, block_apps, block_domains;
    std::string rules_file, bpf_filter;
    
    int opt_start = (mode == "file") ? 4 : ((mode == "live") ? 2 : 2);
    
    for (int i = opt_start; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--block-ip" && i + 1 < argc) block_ips.push_back(argv[++i]);
        else if (arg == "--block-app" && i + 1 < argc) block_apps.push_back(argv[++i]);
        else if (arg == "--block-domain" && i + 1 < argc) block_domains.push_back(argv[++i]);
        else if (arg == "--rules" && i + 1 < argc) rules_file = argv[++i];
        else if (arg == "--fps" && i + 1 < argc) config.num_fps = std::stoi(argv[++i]);
        else if (arg == "--control") config.enable_control = true;
        else if (arg == "--stats") config.enable_stats_stream = true;
        else if (arg == "--filter" && i + 1 < argc) bpf_filter = argv[++i];
        else if (arg == "--help" || arg == "-h") { printUsage(argv[0]); return 0; }
    }
    
    // Set up signal handling
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
    
    // Create engine
    DPIEngine engine(config);
    g_engine = &engine;
    
    if (!engine.initialize()) {
        std::cerr << "Failed to initialize DPI engine\n";
        return 1;
    }
    
    // Load rules
    if (!rules_file.empty()) engine.loadRules(rules_file);
    for (const auto& ip : block_ips) engine.blockIP(ip);
    for (const auto& app : block_apps) engine.blockApp(app);
    for (const auto& dom : block_domains) engine.blockDomain(dom);
    
    // ============================================================
    // File processing mode
    // ============================================================
    if (mode == "file") {
        if (argc < 4) {
            std::cerr << "Error: file mode requires <input.pcap> <output.pcap>\n";
            return 1;
        }
        
        std::string input_file = argv[2];
        std::string output_file = argv[3];
        
        if (!engine.processFile(input_file, output_file)) {
            std::cerr << "Failed to process file\n";
            return 1;
        }
        
        std::cout << "\nProcessing complete! Output: " << output_file << "\n";
    }
    // ============================================================
    // Live capture mode
    // ============================================================
    else if (mode == "live") {
        // Determine interface
        std::string interface;
        if (argc > 2 && argv[2][0] != '-') {
            interface = argv[2];
        } else {
            interface = LiveCapturer::getDefaultInterface();
            if (interface.empty()) {
                std::cerr << "Error: No default interface found. Specify one explicitly.\n";
                return 1;
            }
        }
        
        std::cout << "\n[Daemon] Live capture mode on interface: " << interface << "\n";
        
        LiveCapturer capturer;
        g_capturer = &capturer;
        
        if (!capturer.open(interface)) {
            std::cerr << "Failed to open interface: " << interface << "\n";
            return 1;
        }
        
        if (!bpf_filter.empty()) {
            capturer.setFilter(bpf_filter);
        }
        
        // Start engine threads (FPs, control, stats)
        engine.start();
        
        FiveTupleHash hasher;
        int total_fps = config.num_fps;
        
        std::cout << "[Daemon] Capturing live traffic (Ctrl+C to stop)...\n\n";
        
        // Capture loop - runs until signal
        capturer.startCapture([&](const RawPacket& raw) {
            ParsedPacket parsed;
            if (!PacketParser::parse(raw, parsed)) return;
            if (!parsed.has_ip || (!parsed.has_tcp && !parsed.has_udp)) return;
            
            // Build 5-tuple
            auto parseIP = [](const std::string& ip) -> uint32_t {
                uint32_t result = 0;
                int octet = 0, shift = 0;
                for (char c : ip) {
                    if (c == '.') { result |= (octet << shift); shift += 8; octet = 0; }
                    else if (c >= '0' && c <= '9') octet = octet * 10 + (c - '0');
                }
                return result | (octet << shift);
            };
            
            PacketJob job;
            job.packet_id = 0;
            job.ts_sec = raw.header.ts_sec;
            job.ts_usec = raw.header.ts_usec;
            job.tcp_flags = parsed.tcp_flags;
            job.data = raw.data;
            
            job.tuple.src_ip = parseIP(parsed.src_ip);
            job.tuple.dst_ip = parseIP(parsed.dest_ip);
            job.tuple.src_port = parsed.src_port;
            job.tuple.dst_port = parsed.dest_port;
            job.tuple.protocol = parsed.protocol;
            
            // Calculate payload offset
            job.eth_offset = 0;
            job.ip_offset = 14;
            if (job.data.size() > 14) {
                uint8_t ip_ihl = job.data[14] & 0x0F;
                job.transport_offset = 14 + ip_ihl * 4;
                
                if (parsed.has_tcp && job.transport_offset + 12 < job.data.size()) {
                    uint8_t tcp_off = (job.data[job.transport_offset + 12] >> 4) & 0x0F;
                    job.payload_offset = job.transport_offset + tcp_off * 4;
                } else if (parsed.has_udp) {
                    job.payload_offset = job.transport_offset + 8;
                }
                
                if (job.payload_offset < job.data.size()) {
                    job.payload_length = job.data.size() - job.payload_offset;
                    job.payload_data = job.data.data() + job.payload_offset;
                }
            }
            
            // Direct dispatch to FP
            engine.submitPacket(std::move(job));
        });
        
        // After capture ends
        engine.stop();
        
        std::cout << "\n" << engine.generateReport();
        std::cout << engine.generateClassificationReport();
    }
    else {
        std::cerr << "Unknown mode: " << mode << "\n";
        printUsage(argv[0]);
        return 1;
    }
    
    g_engine = nullptr;
    g_capturer = nullptr;
    return 0;
}
