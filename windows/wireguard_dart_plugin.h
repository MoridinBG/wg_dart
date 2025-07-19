#ifndef FLUTTER_PLUGIN_WIREGUARD_DART_PLUGIN_H_
#define FLUTTER_PLUGIN_WIREGUARD_DART_PLUGIN_H_

#include <flutter/method_channel.h>
#include <flutter/plugin_registrar_windows.h>

#include <memory>
#include <optional>
#include <vector>

#include "connection_status_observer.h"
#include "service_control.h"
#include "wireguard_adapter.h"
#include "wireguard_library.h"

namespace spdlog {
class logger;
}  // namespace spdlog

namespace wireguard_dart {

enum class WireguardMethod {
  GENERATE_KEY_PAIR,
  CHECK_TUNNEL_CONFIGURATION,
  NATIVE_INIT,
  SETUP_TUNNEL,
  CONNECT,
  DISCONNECT,
  STATUS
};

class WireguardDartPlugin : public flutter::Plugin {
 public:
  static void RegisterWithRegistrar(flutter::PluginRegistrarWindows* registrar);

  WireguardDartPlugin();

  virtual ~WireguardDartPlugin();

  // Disallow copy and assign.
  WireguardDartPlugin(const WireguardDartPlugin&) = delete;
  WireguardDartPlugin& operator=(const WireguardDartPlugin&) = delete;

 private:
  // Called when a method is called on this plugin's channel from Dart.
  void HandleMethodCall(const flutter::MethodCall<flutter::EncodableValue>& method_call,
                        std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result);

  // Helper methods for each supported method
  std::optional<WireguardMethod> GetMethodFromString(const std::string& method_name);
  void HandleGenerateKeyPair(const flutter::EncodableMap* args,
                             std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result);
  void HandleCheckTunnelConfiguration(const flutter::EncodableMap* args,
                                      std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result);
  void HandleNativeInit(const flutter::EncodableMap* args,
                        std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result);
  void HandleSetupTunnel(const flutter::EncodableMap* args,
                         std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result);
  void HandleConnect(const flutter::EncodableMap* args,
                     std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result);
  void HandleDisconnect(const flutter::EncodableMap* args,
                        std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result);
  void HandleStatus(const flutter::EncodableMap* args,
                    std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result);

  // Helper method to find adapter by name
  WireguardAdapter* FindAdapterByName(const std::wstring& adapter_name);

  std::unique_ptr<ServiceControl> tunnel_service_;
  std::unique_ptr<ConnectionStatusObserver> connection_status_observer_;
  std::shared_ptr<spdlog::logger> logger_;

  std::shared_ptr<WireguardLibrary> wg_library_;
  std::vector<std::unique_ptr<WireguardAdapter>> adapters_;
};

}  // namespace wireguard_dart

#endif  // FLUTTER_PLUGIN_WIREGUARD_DART_PLUGIN_H_
