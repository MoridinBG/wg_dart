#pragma once

#include <winsock2.h>
#include <ws2ipdef.h>
#include <windows.h>
#include <iphlpapi.h>
#include <netioapi.h>

#include <vector>
#include <memory>
#include <string>
#include "wireguard.h"

namespace spdlog {
class logger;
}

namespace wireguard_dart {

/**
 * Handles network interface configuration for WireGuard adapters.
 * Manages IP addresses and routing table entries.
 */
class WireguardNetworkConfig {
public:
  explicit WireguardNetworkConfig(const NET_LUID &luid);

  // IP address configuration
  bool ConfigureIPAddresses(const std::vector<WIREGUARD_ALLOWED_IP> &addresses);
  bool RemoveIPAddresses();

  // Route configuration
  bool ConfigureRoutes(const std::vector<WIREGUARD_ALLOWED_IP> &allowed_ips);
  bool RemoveRoutes();

private:
  // Helper methods for address string conversion
  static std::string AddressWithCidrToString(const WIREGUARD_ALLOWED_IP &addr);
  static std::string AddressWithCidrToString(const SOCKADDR_INET &addr, UINT8 cidr);

  NET_LUID luid_;
  std::shared_ptr<spdlog::logger> logger_;
};

} // namespace wireguard_dart
