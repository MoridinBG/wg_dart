import 'package:wireguard_dart/key_pair.dart';
import 'package:wireguard_dart/tunnel_statistics.dart';

import 'connection_status.dart';
import 'wireguard_dart_platform_interface.dart';

class WireguardDart {
  Future<KeyPair> generateKeyPair() {
    return WireguardDartPlatform.instance.generateKeyPair();
  }

  Future<void> nativeInit() {
    return WireguardDartPlatform.instance.nativeInit();
  }

  Future<Map<String, dynamic>?> setupTunnel({
    required String bundleId,
    required String tunnelName,
    required String cfg,
  }) {
    return WireguardDartPlatform.instance.setupTunnel(
      bundleId: bundleId,
      tunnelName: tunnelName,
      cfg: cfg,
    );
  }

  Future<void> connect({
    required String tunnelName,
  }) {
    return WireguardDartPlatform.instance.connect(tunnelName: tunnelName);
  }

  Future<void> disconnect({required String tunnelName}) {
    return WireguardDartPlatform.instance.disconnect(tunnelName: tunnelName);
  }

  Future<ConnectionStatus> status() {
    return WireguardDartPlatform.instance.status();
  }

  Stream<ConnectionStatus> statusStream() {
    return WireguardDartPlatform.instance.statusStream();
  }

  Future<bool> checkTunnelConfiguration({required String bundleId, required String tunnelName}) {
    return WireguardDartPlatform.instance.checkTunnelConfiguration(
      bundleId: bundleId,
      tunnelName: tunnelName,
    );
  }

  Future<void> removeTunnelConfiguration({required String bundleId, required String tunnelName}) {
    return WireguardDartPlatform.instance.removeTunnelConfiguration(
      bundleId: bundleId,
      tunnelName: tunnelName,
    );
  }

  Future<TunnelStatistics?> getTunnelStatistics() {
    return WireguardDartPlatform.instance.getTunnelStatistics();
  }
}
