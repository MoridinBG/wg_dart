#include "wireguard_dart_plugin.h"

// This must be included before many other Windows headers.
#include <flutter/event_channel.h>
#include <flutter/event_stream_handler_functions.h>
#include <flutter/method_channel.h>
#include <flutter/plugin_registrar_windows.h>
#include <flutter/standard_method_codec.h>
#include <libbase64.h>
#include <windows.h>

#include <memory>
#include <sstream>

#include "config_writer.h"
#include "connection_status.h"
#include "connection_status_observer.h"
#include "key_generator.h"
#include "service_control.h"
#include "spdlog/spdlog.h"
#include "tunnel.h"
#include "utils.h"
#include "wireguard.h"
#include "wireguard_adapter.h"
#include "wireguard_library.h"

// Declare the function prototype
std::string GetLastErrorAsString(DWORD error_code);

namespace wireguard_dart {

// static
void WireguardDartPlugin::RegisterWithRegistrar(flutter::PluginRegistrarWindows *registrar) {
  auto channel = std::make_unique<flutter::MethodChannel<flutter::EncodableValue>>(
      registrar->messenger(), "wireguard_dart", &flutter::StandardMethodCodec::GetInstance());

  auto plugin = std::make_unique<WireguardDartPlugin>();

  channel->SetMethodCallHandler([plugin_pointer = plugin.get()](const auto &call, auto result) {
    plugin_pointer->HandleMethodCall(call, std::move(result));
  });

  auto status_channel = std::make_unique<flutter::EventChannel<flutter::EncodableValue>>(
      registrar->messenger(), "wireguard_dart/status", &flutter::StandardMethodCodec::GetInstance());

  plugin->connection_status_observer_ = std::make_unique<ConnectionStatusObserver>();
  auto status_channel_handler = std::make_unique<flutter::StreamHandlerFunctions<>>(
      [plugin_pointer = plugin.get()](
          const flutter::EncodableValue *args,
          std::unique_ptr<flutter::EventSink<>> &&events) -> std::unique_ptr<flutter::StreamHandlerError<>> {
        return plugin_pointer->connection_status_observer_->OnListen(args, std::move(events));
      },
      [plugin_pointer =
           plugin.get()](const flutter::EncodableValue *arguments) -> std::unique_ptr<flutter::StreamHandlerError<>> {
        return plugin_pointer->connection_status_observer_->OnCancel(arguments);
      });

  status_channel->SetStreamHandler(std::move(status_channel_handler));

  registrar->AddPlugin(std::move(plugin));
}

WireguardDartPlugin::WireguardDartPlugin() {
  // Initialize logger
  try {
    logger_ = spdlog::get("wireguard_dart");
    if (!logger_) {
      logger_ = spdlog::default_logger();
      logger_->info("WireguardDartPlugin initialized with default logger");
    }
  } catch (const std::exception &e) {
    // Fallback to default logger if initialization fails
    logger_ = spdlog::default_logger();
    logger_->warn("Failed to initialize named logger, using default: {}", e.what());
  }
}

WireguardDartPlugin::~WireguardDartPlugin() { this->connection_status_observer_.get()->StopObserving(); }

std::optional<WireguardMethod> WireguardDartPlugin::GetMethodFromString(const std::string &method_name) {
  if (method_name == "generateKeyPair") return WireguardMethod::GENERATE_KEY_PAIR;
  if (method_name == "checkTunnelConfiguration") return WireguardMethod::CHECK_TUNNEL_CONFIGURATION;
  if (method_name == "nativeInit") return WireguardMethod::NATIVE_INIT;
  if (method_name == "setupTunnel") return WireguardMethod::SETUP_TUNNEL;
  if (method_name == "connect") return WireguardMethod::CONNECT;
  if (method_name == "disconnect") return WireguardMethod::DISCONNECT;
  if (method_name == "status") return WireguardMethod::STATUS;
  return std::nullopt;
}

void WireguardDartPlugin::HandleMethodCall(const flutter::MethodCall<flutter::EncodableValue> &call,
                                           std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result) {
  const auto *args = std::get_if<flutter::EncodableMap>(call.arguments());

  auto method = GetMethodFromString(call.method_name());

  if (!method.has_value()) {
    result->NotImplemented();
    return;
  }

  switch (method.value()) {
    case WireguardMethod::GENERATE_KEY_PAIR:
      HandleGenerateKeyPair(args, std::move(result));
      break;
    case WireguardMethod::CHECK_TUNNEL_CONFIGURATION:
      HandleCheckTunnelConfiguration(args, std::move(result));
      break;
    case WireguardMethod::NATIVE_INIT:
      HandleNativeInit(args, std::move(result));
      break;
    case WireguardMethod::SETUP_TUNNEL:
      HandleSetupTunnel(args, std::move(result));
      break;
    case WireguardMethod::CONNECT:
      HandleConnect(args, std::move(result));
      break;
    case WireguardMethod::DISCONNECT:
      HandleDisconnect(args, std::move(result));
      break;
    case WireguardMethod::STATUS:
      HandleStatus(args, std::move(result));
      break;
  }
}

void WireguardDartPlugin::HandleGenerateKeyPair(
    const flutter::EncodableMap *args, std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result) {
  logger_->info("Generate key pair initiated");
  std::pair public_private_keypair = GenerateKeyPair();
  std::map<flutter::EncodableValue, flutter::EncodableValue> return_value;
  return_value[flutter::EncodableValue("publicKey")] = flutter::EncodableValue(public_private_keypair.first);
  return_value[flutter::EncodableValue("privateKey")] = flutter::EncodableValue(public_private_keypair.second);
  result->Success(flutter::EncodableValue(return_value));
  logger_->info("Generate key pair completed successfully");
}

void WireguardDartPlugin::HandleCheckTunnelConfiguration(
    const flutter::EncodableMap *args, std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result) {
  logger_->info("Check tunnel configuration initiated");

  // Check if we have any adapters created or if the service exists
  bool has_adapter = !adapters_.empty() && adapters_.back() && adapters_.back()->IsValid();
  bool has_service = this->tunnel_service_.get() != nullptr;
  bool is_configured = has_adapter || has_service;

  result->Success(flutter::EncodableValue(is_configured));
  logger_->info("Check tunnel configuration completed - configured: {}, adapter: {}, service: {}", is_configured,
                has_adapter, has_service);
}

void WireguardDartPlugin::HandleNativeInit(const flutter::EncodableMap *args,
                                           std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result) {
  logger_->info("Native init initiated");

  // Initialize WireGuard library
  wg_library_ = WireguardLibrary::Create();
  if (wg_library_) {
    logger_->info("WireGuard library loaded successfully");
  } else {
    logger_->error("Failed to load WireGuard library - adapter management will not be possible");
    result->Error("Failed to load WireGuard library");
    return;
  }

  // Disable packet forwarding that conflicts with WireGuard
  ServiceControl remoteAccessService = ServiceControl(L"RemoteAccess");
  try {
    remoteAccessService.Stop();
  } catch (std::exception &e) {
    logger_->error("Failed to stop RemoteAccess service: {}", e.what());
    result->Error(std::string("Could not stop packet forwarding: ").append(e.what()));
    return;
  }
  try {
    remoteAccessService.Disable();
  } catch (std::exception &e) {
    logger_->error("Failed to disable RemoteAccess service: {}", e.what());
    result->Error(std::string("Could not disable packet forwarding: ").append(e.what()));
    return;
  }
  result->Success();
  logger_->info("Native init completed successfully");
}

void WireguardDartPlugin::HandleSetupTunnel(const flutter::EncodableMap *args,
                                            std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result) {
  logger_->info("Setup tunnel initiated");
  const auto *arg_service_name = std::get_if<std::string>(ValueOrNull(*args, "win32ServiceName"));
  if (arg_service_name == NULL) {
    logger_->error("Setup tunnel failed: win32ServiceName argument missing");
    result->Error("Argument 'win32ServiceName' is required");
    return;
  }

  std::wstring adapter_name = Utf8ToWide(*arg_service_name);

  // Check if WireGuard library is available
  if (!wg_library_ || !wg_library_->IsLoaded()) {
    logger_->error("Setup tunnel failed: WireGuard library not available");
    result->Error("WIREGUARD_LIBRARY_NOT_AVAILABLE", "WireGuard library is not loaded");
    return;
  }

  // Check if adapter already exists
  for (const auto &adapter : adapters_) {
    if (adapter && adapter->GetName() == adapter_name) {
      logger_->info("Setup tunnel completed - adapter already exists: {}", *arg_service_name);
      // Ensure the observer is started
      this->connection_status_observer_.get()->StartObserving(adapter_name);
      result->Success();
      return;
    }
  }

  // Try to open existing adapter first
  auto adapter = WireguardAdapter::Open(wg_library_, adapter_name);
  if (!adapter) {
    // If opening fails, create a new adapter
    logger_->info("Creating new WireGuard adapter: {}", *arg_service_name);
    adapter = WireguardAdapter::Create(wg_library_, adapter_name);
    if (!adapter) {
      DWORD error_code = GetLastError();
      std::string error_message = "Failed to create WireGuard adapter: " + *arg_service_name;
      if (error_code != 0) {
        error_message += " Windows Error Code: " + std::to_string(error_code) + ".";
        error_message += " Description: " + GetLastErrorAsString(error_code);
      }
      logger_->error("Setup tunnel failed: {}", error_message);
      result->Error("ADAPTER_CREATION_FAILED", error_message);
      return;
    }
    logger_->info("WireGuard adapter created successfully: {}", *arg_service_name);
  } else {
    logger_->info("Opened existing WireGuard adapter: {}", *arg_service_name);
  }

  // Store the adapter
  adapters_.push_back(std::move(adapter));

  result->Success();
}

void WireguardDartPlugin::HandleConnect(const flutter::EncodableMap *args,
                                        std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result) {
  logger_->info("Connect initiated");
  auto tunnel_service = this->tunnel_service_.get();
  if (tunnel_service == nullptr) {
    logger_->error("Connect failed: tunnel service not initialized");
    result->Error("Invalid state: call 'setupTunnel' first");
    return;
  }
  const auto *cfg = std::get_if<std::string>(ValueOrNull(*args, "cfg"));
  if (cfg == NULL) {
    logger_->error("Connect failed: cfg argument missing");
    result->Error("Argument 'cfg' is required");
    return;
  }

  std::wstring wg_config_filename;
  try {
    wg_config_filename = WriteConfigToTempFile(*cfg);
  } catch (std::exception &e) {
    logger_->error("Connect failed: could not write config file: {}", e.what());
    result->Error(std::string("Could not write wireguard config: ").append(e.what()));
    return;
  }

  wchar_t module_filename[MAX_PATH];
  GetModuleFileName(NULL, module_filename, MAX_PATH);
  auto current_exec_dir = std::wstring(module_filename);
  current_exec_dir = current_exec_dir.substr(0, current_exec_dir.find_last_of(L"\\/"));

  std::wostringstream service_exec_builder;
  service_exec_builder << current_exec_dir << "\\wireguard_svc.exe" << L" -service" << L" -config-file=\""
                       << wg_config_filename << "\"";
  std::wstring service_exec = service_exec_builder.str();

  try {
    CreateArgs csa = {};
    csa.description = tunnel_service->service_name_ + L" WireGuard tunnel";
    csa.executable_and_args = service_exec;
    csa.dependencies = L"Nsi\0TcpIp\0";
    tunnel_service->Create(csa);
  } catch (std::exception &e) {
    logger_->error("Connect failed: service creation error: {}", e.what());
    result->Error(std::string(e.what()));
    return;
  }
  this->connection_status_observer_.get()->StartObserving(L"");
  try {
    tunnel_service->Start();
  } catch (const std::runtime_error &e) {
    // Handle runtime errors with a specific error code and detailed message
    std::string error_message = "Runtime error while starting the tunnel service: ";
    error_message += e.what();
    logger_->error("Connect failed: {}", error_message);
    result->Error("RUNTIME_ERROR", error_message);  // Error code: RUNTIME_ERROR
    return;
  } catch (const std::exception &e) {
    // Handle service exceptions with a specific error code and detailed message
    DWORD error_code = GetLastError();  // Retrieve the last Windows error code
    std::string error_message = "Exception while starting the tunnel service: ";
    error_message += e.what();
    if (error_code != 0) {
      error_message += " Windows Error Code: " + std::to_string(error_code) + ".";
      error_message += " Description: " + GetLastErrorAsString(error_code);
    }
    logger_->error("Connect failed: {}", error_message);
    result->Error("SERVICE_EXCEPTION", error_message);  // Error code: SERVICE_EXCEPTION
    return;
  } catch (...) {
    // Handle unknown exceptions with additional details
    DWORD error_code = GetLastError();  // Retrieve the last Windows error code
    std::string error_message = "An unknown error occurred while starting the tunnel service.";
    if (error_code != 0) {
      error_message += " Windows Error Code: " + std::to_string(error_code) + ".";
      error_message += " Description: " + GetLastErrorAsString(error_code);
    }
    logger_->error("Connect failed: {}", error_message);
    result->Error("UNKNOWN_ERROR", error_message);  // Error code: UNKNOWN_ERROR
    return;
  }
  result->Success();
  logger_->info("Connect completed successfully");
}

void WireguardDartPlugin::HandleDisconnect(const flutter::EncodableMap *args,
                                           std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result) {
  logger_->info("Disconnect initiated");
  auto tunnel_service = this->tunnel_service_.get();
  if (tunnel_service == nullptr) {
    logger_->error("Disconnect failed: tunnel service not initialized");
    result->Error("Invalid state: call 'setupTunnel' first");
    return;
  }

  try {
    tunnel_service->Stop();
  } catch (const std::runtime_error &e) {
    // Handle runtime errors with a specific error code and detailed message
    std::string error_message = "Runtime error while stopping the tunnel service: ";
    error_message += e.what();
    logger_->error("Disconnect failed: {}", error_message);
    result->Error("RUNTIME_ERROR", error_message);  // Error code: RUNTIME_ERROR
    return;
  } catch (const std::exception &e) {
    // Handle service exceptions with a specific error code and detailed message
    DWORD error_code = GetLastError();  // Retrieve the last Windows error code
    std::string error_message = "Exception while stopping the tunnel service: ";
    error_message += e.what();
    if (error_code != 0) {
      error_message += " Windows Error Code: " + std::to_string(error_code) + ".";
      error_message += " Description: " + GetLastErrorAsString(error_code);
    }
    logger_->error("Disconnect failed: {}", error_message);
    result->Error("SERVICE_EXCEPTION", error_message);  // Error code: SERVICE_EXCEPTION
    return;
  } catch (...) {
    // Handle unknown exceptions with additional details
    DWORD error_code = GetLastError();  // Retrieve the last Windows error code
    std::string error_message = "An unknown error occurred while stopping the tunnel service.";
    if (error_code != 0) {
      error_message += " Windows Error Code: " + std::to_string(error_code) + ".";
      error_message += " Description: " + GetLastErrorAsString(error_code);
    }
    logger_->error("Disconnect failed: {}", error_message);
    result->Error("UNKNOWN_ERROR", error_message);  // Error code: UNKNOWN_ERROR
    return;
  }

  result->Success();
  logger_->info("Disconnect completed successfully");
}

void WireguardDartPlugin::HandleStatus(const flutter::EncodableMap *args,
                                       std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result) {
  logger_->info("Status check initiated");
  auto tunnel_service = this->tunnel_service_.get();
  if (tunnel_service == nullptr) {
    logger_->info("Status check completed - service not initialized, returning disconnected");
    return result->Success(ConnectionStatusToString(ConnectionStatus::disconnected));
  }

  try {
    auto status = tunnel_service->Status();
    result->Success(ConnectionStatusToString(status));
    logger_->info("Status check completed - status: {}", ConnectionStatusToString(status));
  } catch (std::exception &e) {
    logger_->error("Status check failed: {}", e.what());
    result->Error(std::string(e.what()));
  }
}
}  // namespace wireguard_dart

std::string GetLastErrorAsString(DWORD error_code) {
  if (error_code == 0) {
    return "No error.";
  }

  LPSTR message_buffer = nullptr;
  size_t size =
      FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL,
                     error_code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&message_buffer, 0, NULL);

  std::string message;
  if (size != 0 && message_buffer != nullptr) {
    message.assign(message_buffer, size);
    LocalFree(message_buffer);
  } else {
    message = "Unknown error code: " + std::to_string(error_code);
  }
  return message;
}
