#include <iostream>
#include <string>
#include <sstream>
#include <vector>
#include "dpi_engine.h"

using namespace DPI;

void printUsage(const char* program) {
    std::cout << R"(
╔══════════════════════════════════════════════════════════════╗
║              DPI ENGINE v2.0 (Direct Dispatch)              ║
║               Deep Packet Inspection System                 ║
╚══════════════════════════════════════════════════════════════╝

Usage: )" << program << R"( <input.pcap> <output.pcap> [options]

Arguments:
  input.pcap     Input PCAP file (captured user traffic)
  output.pcap    Output PCAP file (filtered traffic to internet)

Options:
  --block-ip <ip>        Block packets from source IP
  --block-app <app>      Block application (e.g., YouTube, Facebook)
  --block-domain <dom>   Block domain (supports wildcards: *.facebook.com)
  --rules <file>         Load blocking rules from file
  --fps <n>              Number of FastPath threads (default: 4)
  --control              Enable UDP control socket (port 5005)
  --stats                Enable UDP stats streaming (port 5006)
  --verbose              Enable verbose output

Examples:
  )" << program << R"( capture.pcap filtered.pcap
  )" << program << R"( capture.pcap filtered.pcap --block-app YouTube
  )" << program << R"( capture.pcap filtered.pcap --block-ip 192.168.1.50 --block-domain *.tiktok.com
  )" << program << R"( capture.pcap filtered.pcap --control --stats --fps 4

Supported Apps for Blocking:
  Google, YouTube, Facebook, Instagram, Twitter/X, Netflix, Amazon,
  Microsoft, Apple, WhatsApp, Telegram, TikTok, Spotify, Zoom, Discord, GitHub

Architecture (v2.0 - Direct Dispatch):
  ┌─────────────┐
  │ PCAP Reader │  Reads packets from input file
  └──────┬──────┘
         │ hash(5-tuple) % num_fps (DIRECT DISPATCH)
         ▼
  ┌──────┴──────────────┐
  │ Fast Path Processors│  N FP threads: DPI, classification, blocking
  │  FP0  FP1  FP2  FP3│
  └──────┬──────────────┘
         │
         ▼
  ┌──────┴──────────────┐
  │   Output Writer     │  Writes forwarded packets to output PCAP
  └─────────────────────┘

  Optional:
  ┌─────────────────────┐
  │ UDP Control (5005)  │  Receives BLOCK_IP, BLOCK_APP, etc.
  ├─────────────────────┤
  │ UDP Stats   (5006)  │  Streams JSON stats every 1 second
  └─────────────────────┘

)";
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        printUsage(argv[0]);
        return 1;
    }
    
    std::string input_file = argv[1];
    std::string output_file = argv[2];
    
    // Parse options
    DPIEngine::Config config;
    config.num_fps = 4;
    
    std::vector<std::string> block_ips;
    std::vector<std::string> block_apps;
    std::vector<std::string> block_domains;
    std::string rules_file;
    
    for (int i = 3; i < argc; i++) {
        std::string arg = argv[i];
        
        if (arg == "--block-ip" && i + 1 < argc) {
            block_ips.push_back(argv[++i]);
        } else if (arg == "--block-app" && i + 1 < argc) {
            block_apps.push_back(argv[++i]);
        } else if (arg == "--block-domain" && i + 1 < argc) {
            block_domains.push_back(argv[++i]);
        } else if (arg == "--rules" && i + 1 < argc) {
            rules_file = argv[++i];
        } else if (arg == "--fps" && i + 1 < argc) {
            config.num_fps = std::stoi(argv[++i]);
        } else if (arg == "--control") {
            config.enable_control = true;
        } else if (arg == "--stats") {
            config.enable_stats_stream = true;
        } else if (arg == "--verbose") {
            config.verbose = true;
        } else if (arg == "--help" || arg == "-h") {
            printUsage(argv[0]);
            return 0;
        }
    }
    
    // Create DPI engine
    DPIEngine engine(config);
    
    // Initialize
    if (!engine.initialize()) {
        std::cerr << "Failed to initialize DPI engine\n";
        return 1;
    }
    
    // Load rules from file if specified
    if (!rules_file.empty()) {
        engine.loadRules(rules_file);
    }
    
    // Apply command-line blocking rules
    for (const auto& ip : block_ips) {
        engine.blockIP(ip);
    }
    
    for (const auto& app : block_apps) {
        engine.blockApp(app);
    }
    
    for (const auto& domain : block_domains) {
        engine.blockDomain(domain);
    }
    
    // Process the file
    if (!engine.processFile(input_file, output_file)) {
        std::cerr << "Failed to process file\n";
        return 1;
    }
    
    std::cout << "\nProcessing complete!\n";
    std::cout << "Output written to: " << output_file << "\n";
    
    return 0;
}
