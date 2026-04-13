#include "TunDevice.hpp"
#include "UdpTransport.hpp"

class TunnelEngine {
public:
    TunnelEngine(TunDevice& tun, UdpTransport& udp);
    void run();

private:
    TunDevice& tun_;
    UdpTransport& udp_;
};
