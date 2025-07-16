#pragma once

#include <windows.h>

#include <memory>
#include <string>

#include "wireguard.h"
#include "wireguard_library.h"

namespace wireguard_dart {

/**
 * Represents a single WireGuard network adapter.
 * Manages the adapter lifecycle and provides methods for configuration.
 */
class WireguardAdapter {
 public:
  static std::unique_ptr<WireguardAdapter> Create(const std::shared_ptr<WireguardLibrary>& library,
                                                  const std::wstring& name,
                                                  const std::wstring& tunnel_type = L"WireGuard");

  static std::unique_ptr<WireguardAdapter> Open(const std::shared_ptr<WireguardLibrary>& library,
                                                const std::wstring& name);

  ~WireguardAdapter();

  // Disable copy and move
  WireguardAdapter(const WireguardAdapter&) = delete;
  WireguardAdapter& operator=(const WireguardAdapter&) = delete;
  WireguardAdapter(WireguardAdapter&&) = delete;
  WireguardAdapter& operator=(WireguardAdapter&&) = delete;

  // Accessors
  const std::wstring& GetName() const { return name_; }
  WIREGUARD_ADAPTER_HANDLE GetHandle() const { return adapter_handle_; }
  bool IsValid() const { return adapter_handle_ != nullptr; }

  // Adapter state management
  bool SetState(WIREGUARD_ADAPTER_STATE state);
  WIREGUARD_ADAPTER_STATE GetState() const;

  // Configuration management
  bool SetConfiguration(const WIREGUARD_INTERFACE* config, DWORD bytes);
  bool GetConfiguration(WIREGUARD_INTERFACE* config, DWORD* bytes) const;

  // Utility methods
  bool GetLUID(NET_LUID* luid) const;
  bool SetLogging(WIREGUARD_ADAPTER_LOG_STATE log_state);

  // Configuration helper
  bool ApplyConfiguration(const std::string& config_text);

 private:
  WireguardAdapter(const std::shared_ptr<WireguardLibrary>& library, const std::wstring& name);

  std::shared_ptr<WireguardLibrary> library_;
  std::wstring name_;
  WIREGUARD_ADAPTER_HANDLE adapter_handle_ = nullptr;
};

}  // namespace wireguard_dart
