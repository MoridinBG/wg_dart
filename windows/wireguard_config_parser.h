#pragma once

#include <windows.h>
#include <winsock2.h>
#include <ws2ipdef.h>

#include <memory>
#include <string>
#include <vector>

#include "wireguard.h"

namespace wireguard_dart {

/**
 * Represents a parsed WireGuard peer configuration
 */
struct ParsedPeer {
  bool has_public_key = false;
  bool has_preshared_key = false;
  bool has_persistent_keepalive = false;
  bool has_endpoint = false;

  BYTE public_key[WIREGUARD_KEY_LENGTH];
  BYTE preshared_key[WIREGUARD_KEY_LENGTH];
  WORD persistent_keepalive = 0;
  SOCKADDR_INET endpoint;
  std::vector<WIREGUARD_ALLOWED_IP> allowed_ips;
};

/**
 * Represents a parsed WireGuard interface configuration
 */
struct ParsedInterface {
  bool has_private_key = false;
  bool has_public_key = false;
  bool has_listen_port = false;

  BYTE private_key[WIREGUARD_KEY_LENGTH];
  BYTE public_key[WIREGUARD_KEY_LENGTH];
  WORD listen_port = 0;
  std::vector<WIREGUARD_ALLOWED_IP> addresses;
};

/**
 * Parses WireGuard INI-style configuration files and converts them to
 * WIREGUARD_INTERFACE structures suitable for the WireGuard API
 */
class WireguardConfigParser {
 public:
  /**
   * Parse a WireGuard configuration from an INI-style string
   * @param config_text The configuration text to parse
   * @return true if parsing was successful, false otherwise
   */
  bool Parse(const std::string& config_text);

  /**
   * Build a WIREGUARD_INTERFACE structure from the parsed configuration
   * @param buffer Pointer to buffer to write the configuration
   * @param buffer_size Size of the buffer in bytes
   * @return Number of bytes written, or 0 if buffer is too small
   */
  DWORD BuildConfiguration(void* buffer, DWORD buffer_size) const;

  /**
   * Calculate the required buffer size for the configuration
   * @return Required buffer size in bytes
   */
  DWORD CalculateConfigurationSize() const;

  /**
   * Get the parsed interface configuration
   */
  const ParsedInterface& GetInterface() const { return interface_; }

  /**
   * Get the parsed peer configurations
   */
  const std::vector<ParsedPeer>& GetPeers() const { return peers_; }

  /**
   * Clear all parsed data
   */
  void Clear();

 private:
  ParsedInterface interface_;
  std::vector<ParsedPeer> peers_;

  // Helper methods
  bool ParseInterfaceSection(const std::string& section_content);
  bool ParsePeerSection(const std::string& section_content);
  bool ParseKeyValue(const std::string& key, const std::string& value, ParsedInterface& iface);
  bool ParseKeyValue(const std::string& key, const std::string& value, ParsedPeer& peer);

  // Parsing utilities
  bool DecodeBase64Key(const std::string& base64_key, BYTE* key_buffer);
  bool ParseIPAddress(const std::string& ip_str, WIREGUARD_ALLOWED_IP& allowed_ip);
  bool ParseEndpoint(const std::string& endpoint_str, SOCKADDR_INET& endpoint);
  std::vector<std::string> SplitString(const std::string& str, char delimiter);
  std::string TrimString(const std::string& str);
};

}  // namespace wireguard_dart
