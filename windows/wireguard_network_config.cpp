#include "wireguard_network_config.h"

#include <stdexcept>
#include <vector>
#include <ws2tcpip.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

#include "spdlog/spdlog.h"

namespace wireguard_dart {

WireguardNetworkConfig::WireguardNetworkConfig(const NET_LUID &luid) : luid_(luid) {
  // Initialize logger
  try {
    logger_ = spdlog::get("wireguard_dart");
    if (!logger_) {
      logger_ = spdlog::default_logger();
    }
  } catch (const std::exception &) {
    // Fallback to default logger if initialization fails
    logger_ = spdlog::default_logger();
  }
}

bool WireguardNetworkConfig::ConfigureIPAddresses(const std::vector<WIREGUARD_ALLOWED_IP> &addresses) {
  if (addresses.empty()) {
    logger_->info("No IP addresses to configure");
    return true; // No IP addresses to configure - not an error
  }

  logger_->debug("Configuring {} IP address(es)", addresses.size());

  for (const auto &addr : addresses) {
    MIB_UNICASTIPADDRESS_ROW row;
    InitializeUnicastIpAddressEntry(&row);

    row.InterfaceLuid = luid_;
    row.DadState = IpDadStatePreferred;
    row.ValidLifetime = 0xffffffff;     // INFINITE
    row.PreferredLifetime = 0xffffffff; // INFINITE
    row.OnLinkPrefixLength = addr.Cidr;

    std::string addr_str = AddressWithCidrToString(addr);
    if (addr.AddressFamily != AF_INET && addr.AddressFamily != AF_INET6) {
      logger_->warn("Skipping unsupported address family: {}", addr.AddressFamily);
      continue;
    }

    if (addr.AddressFamily == AF_INET) {
      row.Address.Ipv4.sin_family = AF_INET;
      row.Address.Ipv4.sin_addr = addr.Address.V4;
    } else if (addr.AddressFamily == AF_INET6) {
      row.Address.Ipv6.sin6_family = AF_INET6;
      row.Address.Ipv6.sin6_addr = addr.Address.V6;
    }

    logger_->debug("Adding IP address: {}", addr_str);
    DWORD result = CreateUnicastIpAddressEntry(&row);
    if (result != NO_ERROR && result != ERROR_OBJECT_ALREADY_EXISTS) {
      logger_->error("Failed to add IP address {}: Windows error {}", addr_str, result);
      return false;
    } else if (result == ERROR_OBJECT_ALREADY_EXISTS) {
      logger_->debug("IP address {} already exists", addr_str);
    } else {
      logger_->debug("Successfully added IP address: {}", addr_str);
    }
  }

  logger_->debug("IP address configuration completed successfully");
  return true;
}

bool WireguardNetworkConfig::ConfigureRoutes(const std::vector<WIREGUARD_ALLOWED_IP> &allowed_ips) {
  if (allowed_ips.empty()) {
    logger_->info("No routes to configure");
    return true;
  }

  logger_->debug("Configuring routes for {} allowed IP(s)", allowed_ips.size());

  for (const auto &allowed_ip : allowed_ips) {
    MIB_IPFORWARD_ROW2 route;
    InitializeIpForwardEntry(&route);

    route.InterfaceLuid = luid_;
    route.Protocol = MIB_IPPROTO_LOCAL;
    route.Metric = 0; // Use default metric
    route.Age = 0;
    route.ValidLifetime = 0xffffffff;     // INFINITE
    route.PreferredLifetime = 0xffffffff; // INFINITE

    std::string route_str = AddressWithCidrToString(allowed_ip);
    if (allowed_ip.AddressFamily != AF_INET && allowed_ip.AddressFamily != AF_INET6) {
      logger_->warn("Skipping route for unsupported address family: {}", allowed_ip.AddressFamily);
      continue;
    }

    if (allowed_ip.AddressFamily == AF_INET) {
      route.DestinationPrefix.Prefix.Ipv4.sin_family = AF_INET;
      route.DestinationPrefix.Prefix.Ipv4.sin_addr = allowed_ip.Address.V4;
      route.DestinationPrefix.PrefixLength = allowed_ip.Cidr;

      // Set next hop to unspecified (0.0.0.0) for direct routing
      route.NextHop.Ipv4.sin_family = AF_INET;
      route.NextHop.Ipv4.sin_addr.s_addr = 0;
    } else if (allowed_ip.AddressFamily == AF_INET6) {
      route.DestinationPrefix.Prefix.Ipv6.sin6_family = AF_INET6;
      route.DestinationPrefix.Prefix.Ipv6.sin6_addr = allowed_ip.Address.V6;
      route.DestinationPrefix.PrefixLength = allowed_ip.Cidr;

      // Set next hop to unspecified (::) for direct routing
      route.NextHop.Ipv6.sin6_family = AF_INET6;
      memset(&route.NextHop.Ipv6.sin6_addr, 0, sizeof(route.NextHop.Ipv6.sin6_addr));
    }

    logger_->debug("Adding route: {}", route_str);
    DWORD result = CreateIpForwardEntry2(&route);
    if (result != NO_ERROR && result != ERROR_OBJECT_ALREADY_EXISTS) {
      logger_->error("Failed to add route {}: Windows error {}", route_str, result);
      return false;
    } else if (result == ERROR_OBJECT_ALREADY_EXISTS) {
      logger_->debug("Route {} already exists", route_str);
    } else {
      logger_->debug("Successfully added route: {}", route_str);
    }
  }

  logger_->debug("Route configuration completed successfully");
  return true;
}

bool WireguardNetworkConfig::RemoveIPAddresses() {
  PMIB_UNICASTIPADDRESS_TABLE table = nullptr;

  DWORD result = GetUnicastIpAddressTable(AF_UNSPEC, &table);
  if (result != NO_ERROR) {
    logger_->error("Failed to get unicast IP address table: Windows error {}", result);
    return false;
  }

  bool success = true;

  for (ULONG i = 0; i < table->NumEntries; i++) {
    if (table->Table[i].InterfaceLuid.Value == luid_.Value) {
      std::string addr_str = AddressWithCidrToString(table->Table[i].Address, table->Table[i].OnLinkPrefixLength);

      logger_->debug("Removing IP address: {}", addr_str);
      DWORD delete_result = DeleteUnicastIpAddressEntry(&table->Table[i]);
      if (delete_result != NO_ERROR && delete_result != ERROR_NOT_FOUND) {
        logger_->error("Failed to remove IP address {}: Windows error {}", addr_str, delete_result);
        success = false;
      } else {
        if (delete_result == ERROR_NOT_FOUND) {
          logger_->debug("IP address {} was already removed", addr_str);
        } else {
          logger_->debug("Successfully removed IP address: {}", addr_str);
        }
      }
    }
  }

  FreeMibTable(table);
  return success;
}

bool WireguardNetworkConfig::RemoveRoutes() {
  PMIB_IPFORWARD_TABLE2 table = nullptr;

  DWORD result = GetIpForwardTable2(AF_UNSPEC, &table);
  if (result != NO_ERROR) {
    logger_->error("Failed to get IP forward table: Windows error {}", result);
    return false;
  }

  bool success = true;

  for (ULONG i = 0; i < table->NumEntries; i++) {
    if (table->Table[i].InterfaceLuid.Value == luid_.Value) {
      std::string route_str = AddressWithCidrToString(table->Table[i].DestinationPrefix.Prefix,
                                                      table->Table[i].DestinationPrefix.PrefixLength);

      logger_->debug("Removing route: {}", route_str);
      DWORD delete_result = DeleteIpForwardEntry2(&table->Table[i]);
      if (delete_result != NO_ERROR && delete_result != ERROR_NOT_FOUND) {
        logger_->error("Failed to remove route {}: Windows error {}", route_str, delete_result);
        success = false;
      } else {
        if (delete_result == ERROR_NOT_FOUND) {
          logger_->debug("Route {} was already removed", route_str);
        } else {
          logger_->debug("Successfully removed route: {}", route_str);
        }
      }
    }
  }

  FreeMibTable(table);
  return success;
}

std::string WireguardNetworkConfig::AddressWithCidrToString(const WIREGUARD_ALLOWED_IP &addr) {
  char ip_str[INET6_ADDRSTRLEN];

  if (addr.AddressFamily == AF_INET) {
    inet_ntop(AF_INET, &addr.Address.V4, ip_str, INET_ADDRSTRLEN);
  } else if (addr.AddressFamily == AF_INET6) {
    inet_ntop(AF_INET6, &addr.Address.V6, ip_str, INET6_ADDRSTRLEN);
  } else {
    return "unknown address family " + std::to_string(addr.AddressFamily);
  }

  auto addr_str = std::string(ip_str);
  return addr_str + "/" + std::to_string(addr.Cidr);
}

std::string WireguardNetworkConfig::AddressWithCidrToString(const SOCKADDR_INET &addr, UINT8 cidr) {
  char ip_str[INET6_ADDRSTRLEN];

  if (addr.si_family == AF_INET) {
    inet_ntop(AF_INET, &addr.Ipv4.sin_addr, ip_str, INET_ADDRSTRLEN);
  } else if (addr.si_family == AF_INET6) {
    inet_ntop(AF_INET6, &addr.Ipv6.sin6_addr, ip_str, INET6_ADDRSTRLEN);
  } else {
    return "unknown address family " + std::to_string(addr.si_family);
  }

  auto addr_str = std::string(ip_str);
  return addr_str + "/" + std::to_string(cidr);
}

} // namespace wireguard_dart
