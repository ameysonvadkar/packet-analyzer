#ifndef PCAP_LIVE_CAPTURER_H
#define PCAP_LIVE_CAPTURER_H

#include "pcap_reader.h"
#include <string>
#include <functional>
#include <atomic>
#include <vector>

namespace PacketAnalyzer {

// ============================================================================
// Live Packet Capturer - Wraps libpcap for real-time packet capture
// ============================================================================
//
// Uses libpcap to capture packets from a network interface in real-time.
// On macOS, libpcap is pre-installed. On Linux, install libpcap-dev.
//
// Usage:
//   LiveCapturer cap;
//   cap.open("en0");
//   cap.setFilter("tcp port 443");  // Optional BPF filter
//   cap.startCapture([](const RawPacket& pkt) {
//       // Process each packet
//   });
//
// ============================================================================

using PacketCallback = std::function<void(const RawPacket&)>;

class LiveCapturer {
public:
    LiveCapturer() = default;
    ~LiveCapturer();
    
    // Open a network interface for capture
    // interface: "en0", "eth0", "wlan0", "lo0", or "any"
    bool open(const std::string& interface, int snaplen = 65535, int timeout_ms = 100);
    
    // Close the capture handle
    void close();
    
    // Set a BPF filter (e.g., "tcp port 443", "host 192.168.1.1")
    bool setFilter(const std::string& filter);
    
    // Start capturing packets (blocking - call from a dedicated thread)
    // callback is invoked for each captured packet
    void startCapture(PacketCallback callback);
    
    // Stop capturing
    void stopCapture();
    
    // Check if capture is active
    bool isCapturing() const { return capturing_; }
    
    // Get the link-layer header type (for PCAP global header)
    int getLinkType() const { return link_type_; }
    
    // List available network interfaces
    static std::vector<std::string> listInterfaces();
    
    // Auto-detect the default interface
    static std::string getDefaultInterface();

private:
    void* pcap_handle_ = nullptr;  // pcap_t* (opaque to avoid header dependency)
    std::atomic<bool> capturing_{false};
    int link_type_ = 1;  // Default: Ethernet (DLT_EN10MB)
    
    // Internal callback bridge
    static void pcapCallback(unsigned char* user, const void* header, const unsigned char* data);
};

} // namespace PacketAnalyzer

#endif // PCAP_LIVE_CAPTURER_H
