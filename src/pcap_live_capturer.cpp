#include "pcap_live_capturer.h"
#include <iostream>
#include <cstring>

#ifdef HAS_LIBPCAP
#include <pcap/pcap.h>
#endif

namespace PacketAnalyzer {

LiveCapturer::~LiveCapturer() {
    close();
}

bool LiveCapturer::open(const std::string& interface, int snaplen, int timeout_ms) {
#ifdef HAS_LIBPCAP
    char errbuf[PCAP_ERRBUF_SIZE];
    
    pcap_t* handle = pcap_open_live(
        interface.c_str(),
        snaplen,
        1,              // promiscuous mode
        timeout_ms,
        errbuf
    );
    
    if (!handle) {
        std::cerr << "[LiveCapture] Error opening " << interface << ": " << errbuf << "\n";
        return false;
    }
    
    pcap_handle_ = handle;
    link_type_ = pcap_datalink(handle);
    
    std::cout << "[LiveCapture] Opened interface: " << interface << "\n";
    std::cout << "[LiveCapture] Link type: " << link_type_ 
              << (link_type_ == DLT_EN10MB ? " (Ethernet)" : "") << "\n";
    std::cout << "[LiveCapture] Snaplen: " << snaplen << " bytes\n";
    
    return true;
#else
    std::cerr << "[LiveCapture] libpcap not available - live capture disabled\n";
    return false;
#endif
}

void LiveCapturer::close() {
#ifdef HAS_LIBPCAP
    stopCapture();
    if (pcap_handle_) {
        pcap_close(static_cast<pcap_t*>(pcap_handle_));
        pcap_handle_ = nullptr;
    }
#endif
}

bool LiveCapturer::setFilter(const std::string& filter) {
#ifdef HAS_LIBPCAP
    if (!pcap_handle_) return false;
    
    pcap_t* handle = static_cast<pcap_t*>(pcap_handle_);
    struct bpf_program fp;
    
    if (pcap_compile(handle, &fp, filter.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "[LiveCapture] Filter compile error: " << pcap_geterr(handle) << "\n";
        return false;
    }
    
    if (pcap_setfilter(handle, &fp) == -1) {
        std::cerr << "[LiveCapture] Filter set error: " << pcap_geterr(handle) << "\n";
        pcap_freecode(&fp);
        return false;
    }
    
    pcap_freecode(&fp);
    std::cout << "[LiveCapture] Filter set: " << filter << "\n";
    return true;
#else
    return false;
#endif
}

// Internal struct to pass callback context through pcap
struct CaptureContext {
    PacketCallback* callback;
};

void LiveCapturer::pcapCallback(unsigned char* user, const void* header_raw, const unsigned char* data) {
#ifdef HAS_LIBPCAP
    const struct pcap_pkthdr* header = static_cast<const struct pcap_pkthdr*>(header_raw);
    CaptureContext* ctx = reinterpret_cast<CaptureContext*>(user);
    
    RawPacket pkt;
    pkt.header.ts_sec = header->ts.tv_sec;
    pkt.header.ts_usec = header->ts.tv_usec;
    pkt.header.incl_len = header->caplen;
    pkt.header.orig_len = header->len;
    pkt.data.assign(data, data + header->caplen);
    
    (*(ctx->callback))(pkt);
#endif
}

void LiveCapturer::startCapture(PacketCallback callback) {
#ifdef HAS_LIBPCAP
    if (!pcap_handle_) return;
    
    capturing_ = true;
    pcap_t* handle = static_cast<pcap_t*>(pcap_handle_);
    
    CaptureContext ctx;
    ctx.callback = &callback;
    
    std::cout << "[LiveCapture] Starting capture loop...\n";
    
    while (capturing_) {
        struct pcap_pkthdr* header;
        const u_char* data;
        
        int result = pcap_next_ex(handle, &header, &data);
        
        if (result == 1) {
            // Packet received
            RawPacket pkt;
            pkt.header.ts_sec = header->ts.tv_sec;
            pkt.header.ts_usec = header->ts.tv_usec;
            pkt.header.incl_len = header->caplen;
            pkt.header.orig_len = header->len;
            pkt.data.assign(data, data + header->caplen);
            
            callback(pkt);
        } else if (result == 0) {
            // Timeout - continue
            continue;
        } else if (result == -1) {
            std::cerr << "[LiveCapture] Error: " << pcap_geterr(handle) << "\n";
            break;
        } else if (result == -2) {
            // EOF (when reading from file via pcap)
            break;
        }
    }
    
    std::cout << "[LiveCapture] Capture loop ended\n";
    capturing_ = false;
#else
    std::cerr << "[LiveCapture] libpcap not available\n";
#endif
}

void LiveCapturer::stopCapture() {
#ifdef HAS_LIBPCAP
    if (capturing_) {
        capturing_ = false;
        if (pcap_handle_) {
            pcap_breakloop(static_cast<pcap_t*>(pcap_handle_));
        }
    }
#endif
}

std::vector<std::string> LiveCapturer::listInterfaces() {
    std::vector<std::string> interfaces;
#ifdef HAS_LIBPCAP
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs;
    
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "[LiveCapture] Error listing interfaces: " << errbuf << "\n";
        return interfaces;
    }
    
    for (pcap_if_t* dev = alldevs; dev != nullptr; dev = dev->next) {
        interfaces.push_back(dev->name);
    }
    
    pcap_freealldevs(alldevs);
#endif
    return interfaces;
}

std::string LiveCapturer::getDefaultInterface() {
#ifdef HAS_LIBPCAP
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs;
    
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        return "";
    }
    
    std::string default_iface;
    if (alldevs) {
        default_iface = alldevs->name;
    }
    
    pcap_freealldevs(alldevs);
    return default_iface;
#else
    return "";
#endif
}

} // namespace PacketAnalyzer
