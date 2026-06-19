#ifndef DPI_ENGINE_H
#define DPI_ENGINE_H

#include "types.h"
#include "pcap_reader.h"
#include "packet_parser.h"
#include "fast_path.h"
#include "rule_manager.h"
#include "connection_tracker.h"
#include <memory>
#include <thread>
#include <atomic>
#include <fstream>
#include <mutex>

namespace DPI {

// ============================================================================
// DPI Engine v2.0 - Main orchestrator (LB-free architecture)
// ============================================================================
//
// Architecture Overview (simplified from v1.0 - removed LB layer):
//
//   +------------------+
//   |   PCAP Reader    |  (Reads packets from input file or live capture)
//   +--------+---------+
//            |
//            v (hash(5-tuple) % total_fps → direct dispatch)
//   +--------+-------------------+
//   |     Fast Path Processors   |  (N FP threads)
//   |  FP0   FP1   FP2   FP3    |
//   +--------+-------------------+
//            |
//            v
//   +--------+---------+
//   |   Output Queue   |  (Packets to forward)
//   +--------+---------+
//            |
//            v
//   +--------+---------+
//   |  Output Writer   |  (Writes to output PCAP)
//   +-------------------+
//
// Additionally:
//   - Control Thread: listens on UDP port 5005 for rule commands
//   - Stats Thread:   broadcasts JSON metrics on UDP port 5006
//
// ============================================================================

class DPIEngine {
public:
    // Configuration
    struct Config {
        int num_fps = 4;                  // Total number of FastPath threads
        size_t queue_size = 10000;
        std::string rules_file;
        bool verbose = false;
        // UDP control/stats ports
        uint16_t control_port = 5005;
        uint16_t stats_port = 5006;
        bool enable_control = false;      // Enable UDP control socket
        bool enable_stats_stream = false; // Enable UDP stats streaming
    };
    
    DPIEngine(const Config& config);
    ~DPIEngine();
    
    // Initialize the engine (create threads, queues)
    bool initialize();
    
    // Process a PCAP file
    bool processFile(const std::string& input_file, 
                     const std::string& output_file);
    
    // Start the engine (starts all threads)
    void start();
    
    // Stop the engine (stops all threads)
    void stop();
    
    // Wait for processing to complete
    void waitForCompletion();
    
    // Submit a single packet job directly to the engine's pipeline (e.g. from live capturer)
    void submitPacket(PacketJob&& job);
    
    // ========== Rule Management ==========
    
    void blockIP(const std::string& ip);
    void unblockIP(const std::string& ip);
    void blockApp(AppType app);
    void blockApp(const std::string& app_name);
    void unblockApp(AppType app);
    void unblockApp(const std::string& app_name);
    void blockDomain(const std::string& domain);
    void unblockDomain(const std::string& domain);
    bool loadRules(const std::string& filename);
    bool saveRules(const std::string& filename);
    
    // ========== Reporting ==========
    
    std::string generateReport() const;
    std::string generateClassificationReport() const;
    std::string generateJSONStats() const;
    const DPIStats& getStats() const;
    void printStatus() const;
    
    // ========== Accessors ==========
    
    RuleManager& getRuleManager() { return *rule_manager_; }
    const Config& getConfig() const { return config_; }
    bool isRunning() const { return running_; }

private:
    Config config_;
    
    // Shared components
    std::unique_ptr<RuleManager> rule_manager_;
    std::unique_ptr<GlobalConnectionTable> global_conn_table_;
    
    // Thread pool (direct dispatch, no LB layer)
    std::unique_ptr<FPManager> fp_manager_;
    
    // Output handling
    ThreadSafeQueue<PacketJob> output_queue_;
    std::thread output_thread_;
    std::ofstream output_file_;
    std::mutex output_mutex_;
    
    // Statistics
    DPIStats stats_;
    
    // Control
    std::atomic<bool> running_{false};
    std::atomic<bool> processing_complete_{false};
    
    // Reader thread (separate for PCAP input)
    std::thread reader_thread_;
    
    // UDP Control & Stats threads
    std::thread control_thread_;
    std::thread stats_thread_;
    
    // Output handling
    void outputThreadFunc();
    void handleOutput(const PacketJob& job, PacketAction action);
    
    // Write PCAP header to output file
    bool writeOutputHeader(const PacketAnalyzer::PcapGlobalHeader& header);
    
    // Write a packet to output file
    void writeOutputPacket(const PacketJob& job);
    
    // Reader function
    void readerThreadFunc(const std::string& input_file);
    
    // Convert ParsedPacket to PacketJob
    PacketJob createPacketJob(const PacketAnalyzer::RawPacket& raw,
                               const PacketAnalyzer::ParsedPacket& parsed,
                               uint32_t packet_id);
    
    // UDP control thread: listens for rule commands
    void controlThreadFunc();
    
    // UDP stats streaming thread: broadcasts JSON metrics
    void statsThreadFunc();
};

} // namespace DPI

#endif // DPI_ENGINE_H
