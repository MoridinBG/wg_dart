#include "wireguard_config_parser.h"

#include <libbase64.h>
#include <ws2tcpip.h>

#include <algorithm>
#include <sstream>

namespace wireguard_dart {

bool WireguardConfigParser::Parse(const std::string& config_text) {
  Clear();

  std::istringstream stream(config_text);
  std::string line;
  std::string current_section;
  std::string section_content;

  while (std::getline(stream, line)) {
    line = TrimString(line);

    // Skip empty lines and comments
    if (line.empty() || line[0] == '#' || line[0] == ';') {
      continue;
    }

    // Check for section headers
    if (line[0] == '[' && line.back() == ']') {
      // Process previous section
      if (!current_section.empty()) {
        if (current_section == "Interface") {
          if (!ParseInterfaceSection(section_content)) {
            return false;
          }
        } else if (current_section == "Peer") {
          if (!ParsePeerSection(section_content)) {
            return false;
          }
        }
      }

      // Start new section
      current_section = line.substr(1, line.length() - 2);
      section_content.clear();
    } else {
      // Add line to current section content
      if (!section_content.empty()) {
        section_content += "\n";
      }
      section_content += line;
    }
  }

  // Process final section
  if (!current_section.empty()) {
    if (current_section == "Interface") {
      if (!ParseInterfaceSection(section_content)) {
        return false;
      }
    } else if (current_section == "Peer") {
      if (!ParsePeerSection(section_content)) {
        return false;
      }
    }
  }

  return true;
}

bool WireguardConfigParser::ParseInterfaceSection(const std::string& section_content) {
  std::istringstream stream(section_content);
  std::string line;

  while (std::getline(stream, line)) {
    line = TrimString(line);
    if (line.empty()) continue;

    auto equals_pos = line.find('=');
    if (equals_pos == std::string::npos) continue;

    std::string key = TrimString(line.substr(0, equals_pos));
    std::string value = TrimString(line.substr(equals_pos + 1));

    if (!ParseKeyValue(key, value, interface_)) {
      return false;
    }
  }

  return true;
}

bool WireguardConfigParser::ParsePeerSection(const std::string& section_content) {
  ParsedPeer peer;
  std::istringstream stream(section_content);
  std::string line;

  while (std::getline(stream, line)) {
    line = TrimString(line);
    if (line.empty()) continue;

    auto equals_pos = line.find('=');
    if (equals_pos == std::string::npos) continue;

    std::string key = TrimString(line.substr(0, equals_pos));
    std::string value = TrimString(line.substr(equals_pos + 1));

    if (!ParseKeyValue(key, value, peer)) {
      return false;
    }
  }

  peers_.push_back(peer);
  return true;
}

bool WireguardConfigParser::ParseKeyValue(const std::string& key, const std::string& value, ParsedInterface& iface) {
  if (key == "PrivateKey") {
    if (DecodeBase64Key(value, iface.private_key)) {
      iface.has_private_key = true;
      return true;
    }
    return false;
  } else if (key == "PublicKey") {
    if (DecodeBase64Key(value, iface.public_key)) {
      iface.has_public_key = true;
      return true;
    }
    return false;
  } else if (key == "ListenPort") {
    try {
      iface.listen_port = static_cast<WORD>(std::stoul(value));
      iface.has_listen_port = true;
      return true;
    } catch (...) {
      return false;
    }
  } else if (key == "Address") {
    // Parse comma-separated addresses
    auto addresses = SplitString(value, ',');
    for (const auto& addr_str : addresses) {
      WIREGUARD_ALLOWED_IP allowed_ip;
      if (ParseIPAddress(TrimString(addr_str), allowed_ip)) {
        iface.addresses.push_back(allowed_ip);
      } else {
        return false;
      }
    }
    return true;
  }

  // Ignore unknown keys
  return true;
}

bool WireguardConfigParser::ParseKeyValue(const std::string& key, const std::string& value, ParsedPeer& peer) {
  if (key == "PublicKey") {
    if (DecodeBase64Key(value, peer.public_key)) {
      peer.has_public_key = true;
      return true;
    }
    return false;
  } else if (key == "PresharedKey") {
    if (DecodeBase64Key(value, peer.preshared_key)) {
      peer.has_preshared_key = true;
      return true;
    }
    return false;
  } else if (key == "PersistentKeepalive") {
    try {
      peer.persistent_keepalive = static_cast<WORD>(std::stoul(value));
      peer.has_persistent_keepalive = true;
      return true;
    } catch (...) {
      return false;
    }
  } else if (key == "Endpoint") {
    if (ParseEndpoint(value, peer.endpoint)) {
      peer.has_endpoint = true;
      return true;
    }
    return false;
  } else if (key == "AllowedIPs") {
    // Parse comma-separated allowed IPs
    auto ips = SplitString(value, ',');
    for (const auto& ip_str : ips) {
      WIREGUARD_ALLOWED_IP allowed_ip;
      if (ParseIPAddress(TrimString(ip_str), allowed_ip)) {
        peer.allowed_ips.push_back(allowed_ip);
      } else {
        return false;
      }
    }
    return true;
  }

  // Ignore unknown keys
  return true;
}

bool WireguardConfigParser::DecodeBase64Key(const std::string& base64_key, BYTE* key_buffer) {
  if (base64_key.empty()) {
    return false;
  }

  size_t decoded_size = 0;
  if (base64_decode(base64_key.c_str(), base64_key.length(), (char*)key_buffer, &decoded_size, 0) != 1) {
    return false;
  }

  return decoded_size == WIREGUARD_KEY_LENGTH;
}

bool WireguardConfigParser::ParseIPAddress(const std::string& ip_str, WIREGUARD_ALLOWED_IP& allowed_ip) {
  auto slash_pos = ip_str.find('/');
  if (slash_pos == std::string::npos) {
    return false;
  }

  std::string addr_str = ip_str.substr(0, slash_pos);
  std::string cidr_str = ip_str.substr(slash_pos + 1);

  // Parse CIDR
  try {
    allowed_ip.Cidr = static_cast<BYTE>(std::stoul(cidr_str));
  } catch (...) {
    return false;
  }

  // Try IPv4 first
  IN_ADDR addr4;
  if (inet_pton(AF_INET, addr_str.c_str(), &addr4) == 1) {
    allowed_ip.AddressFamily = AF_INET;
    allowed_ip.Address.V4 = addr4;
    return true;
  }

  // Try IPv6
  IN6_ADDR addr6;
  if (inet_pton(AF_INET6, addr_str.c_str(), &addr6) == 1) {
    allowed_ip.AddressFamily = AF_INET6;
    allowed_ip.Address.V6 = addr6;
    return true;
  }

  return false;
}

bool WireguardConfigParser::ParseEndpoint(const std::string& endpoint_str, SOCKADDR_INET& endpoint) {
  // Parse format: "IP:PORT" or "[IPv6]:PORT"

  if (endpoint_str.empty()) {
    return false;
  }

  std::string ip_str;
  std::string port_str;

  if (endpoint_str[0] == '[') {
    // IPv6 format: [::1]:51820
    auto close_bracket = endpoint_str.find(']');
    if (close_bracket == std::string::npos || close_bracket + 1 >= endpoint_str.length() ||
        endpoint_str[close_bracket + 1] != ':') {
      return false;
    }
    ip_str = endpoint_str.substr(1, close_bracket - 1);
    port_str = endpoint_str.substr(close_bracket + 2);
  } else {
    // IPv4 format: 192.168.1.1:51820
    auto colon_pos = endpoint_str.rfind(':');
    if (colon_pos == std::string::npos) {
      return false;
    }
    ip_str = endpoint_str.substr(0, colon_pos);
    port_str = endpoint_str.substr(colon_pos + 1);
  }

  // Parse port
  WORD port;
  try {
    port = static_cast<WORD>(std::stoul(port_str));
  } catch (...) {
    return false;
  }

  // Try IPv4 first
  SOCKADDR_IN* addr4 = &endpoint.Ipv4;
  if (inet_pton(AF_INET, ip_str.c_str(), &addr4->sin_addr) == 1) {
    endpoint.si_family = AF_INET;
    addr4->sin_family = AF_INET;
    addr4->sin_port = htons(port);
    return true;
  }

  // Try IPv6
  SOCKADDR_IN6* addr6 = &endpoint.Ipv6;
  if (inet_pton(AF_INET6, ip_str.c_str(), &addr6->sin6_addr) == 1) {
    endpoint.si_family = AF_INET6;
    addr6->sin6_family = AF_INET6;
    addr6->sin6_port = htons(port);
    return true;
  }

  return false;
}

DWORD WireguardConfigParser::CalculateConfigurationSize() const {
  DWORD size = sizeof(WIREGUARD_INTERFACE);

  for (const auto& peer : peers_) {
    size += sizeof(WIREGUARD_PEER);
    size += static_cast<DWORD>(peer.allowed_ips.size() * sizeof(WIREGUARD_ALLOWED_IP));
  }

  return size;
}

DWORD WireguardConfigParser::BuildConfiguration(void* buffer, DWORD buffer_size) const {
  DWORD required_size = CalculateConfigurationSize();
  if (buffer_size < required_size) {
    return 0;
  }

  BYTE* current_pos = static_cast<BYTE*>(buffer);

  // Build interface structure
  WIREGUARD_INTERFACE* wg_interface = reinterpret_cast<WIREGUARD_INTERFACE*>(current_pos);
  ZeroMemory(wg_interface, sizeof(WIREGUARD_INTERFACE));

  wg_interface->Flags = WIREGUARD_INTERFACE_REPLACE_PEERS;
  if (interface_.has_private_key) {
    wg_interface->Flags =
        static_cast<WIREGUARD_INTERFACE_FLAG>(wg_interface->Flags | WIREGUARD_INTERFACE_HAS_PRIVATE_KEY);
    memcpy(wg_interface->PrivateKey, interface_.private_key, WIREGUARD_KEY_LENGTH);
  }
  if (interface_.has_public_key) {
    wg_interface->Flags =
        static_cast<WIREGUARD_INTERFACE_FLAG>(wg_interface->Flags | WIREGUARD_INTERFACE_HAS_PUBLIC_KEY);
    memcpy(wg_interface->PublicKey, interface_.public_key, WIREGUARD_KEY_LENGTH);
  }
  if (interface_.has_listen_port) {
    wg_interface->Flags =
        static_cast<WIREGUARD_INTERFACE_FLAG>(wg_interface->Flags | WIREGUARD_INTERFACE_HAS_LISTEN_PORT);
    wg_interface->ListenPort = interface_.listen_port;
  }

  wg_interface->PeersCount = static_cast<DWORD>(peers_.size());
  current_pos += sizeof(WIREGUARD_INTERFACE);

  // Build peer structures
  for (const auto& parsed_peer : peers_) {
    WIREGUARD_PEER* peer = reinterpret_cast<WIREGUARD_PEER*>(current_pos);
    ZeroMemory(peer, sizeof(WIREGUARD_PEER));

    peer->Flags = WIREGUARD_PEER_REPLACE_ALLOWED_IPS;

    if (parsed_peer.has_public_key) {
      peer->Flags = static_cast<WIREGUARD_PEER_FLAG>(peer->Flags | WIREGUARD_PEER_HAS_PUBLIC_KEY);
      memcpy(peer->PublicKey, parsed_peer.public_key, WIREGUARD_KEY_LENGTH);
    }

    if (parsed_peer.has_preshared_key) {
      peer->Flags = static_cast<WIREGUARD_PEER_FLAG>(peer->Flags | WIREGUARD_PEER_HAS_PRESHARED_KEY);
      memcpy(peer->PresharedKey, parsed_peer.preshared_key, WIREGUARD_KEY_LENGTH);
    }

    if (parsed_peer.has_persistent_keepalive) {
      peer->Flags = static_cast<WIREGUARD_PEER_FLAG>(peer->Flags | WIREGUARD_PEER_HAS_PERSISTENT_KEEPALIVE);
      peer->PersistentKeepalive = parsed_peer.persistent_keepalive;
    }

    if (parsed_peer.has_endpoint) {
      peer->Flags = static_cast<WIREGUARD_PEER_FLAG>(peer->Flags | WIREGUARD_PEER_HAS_ENDPOINT);
      peer->Endpoint = parsed_peer.endpoint;
    }

    peer->AllowedIPsCount = static_cast<DWORD>(parsed_peer.allowed_ips.size());
    current_pos += sizeof(WIREGUARD_PEER);

    // Build allowed IPs
    for (const auto& allowed_ip : parsed_peer.allowed_ips) {
      WIREGUARD_ALLOWED_IP* wg_allowed_ip = reinterpret_cast<WIREGUARD_ALLOWED_IP*>(current_pos);
      *wg_allowed_ip = allowed_ip;
      current_pos += sizeof(WIREGUARD_ALLOWED_IP);
    }
  }

  return required_size;
}

void WireguardConfigParser::Clear() {
  interface_ = ParsedInterface{};
  peers_.clear();
}

std::vector<std::string> WireguardConfigParser::SplitString(const std::string& str, char delimiter) {
  std::vector<std::string> result;
  std::istringstream stream(str);
  std::string item;

  while (std::getline(stream, item, delimiter)) {
    result.push_back(item);
  }

  return result;
}

std::string WireguardConfigParser::TrimString(const std::string& str) {
  auto start = str.find_first_not_of(" \t\r\n");
  if (start == std::string::npos) {
    return "";
  }

  auto end = str.find_last_not_of(" \t\r\n");
  return str.substr(start, end - start + 1);
}

}  // namespace wireguard_dart
