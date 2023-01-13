{config, pkgs, lib, ...}: {
 
  services.coturn = {
    enable = true;
    use-auth-secret = true;
    static-auth-secret = "${builtins.readFile config.age.secrets.privkey.path}";
    no-cli = true;
    realm = "turn.examplewebsite.com";
    relay-ips = [
      "54.81.126.237"
    ];
    no-tcp-relay = true;
    extraConfig = ''
      verbose
      cipher-list="HIGH"
      no-loopback-peers
      no-multicast-peers
      denied-peer-ip=0.0.0.0-0.255.255.255
      denied-peer-ip=10.0.0.0-10.255.255.255
      denied-peer-ip=100.64.0.0-100.127.255.255
      denied-peer-ip=127.0.0.0-127.255.255.255
      denied-peer-ip=169.254.0.0-169.254.255.255
      denied-peer-ip=172.16.0.0-172.31.255.255
      denied-peer-ip=192.0.0.0-192.0.0.255
      denied-peer-ip=192.0.2.0-192.0.2.255
      denied-peer-ip=192.88.99.0-192.88.99.255
      denied-peer-ip=192.168.0.0-192.168.255.255
      denied-peer-ip=198.18.0.0-198.19.255.255
      denied-peer-ip=198.51.100.0-198.51.100.255
      denied-peer-ip=203.0.113.0-203.0.113.255
      denied-peer-ip=240.0.0.0-255.255.255.255
      denied-peer-ip=::1
      denied-peer-ip=64:ff9b::-64:ff9b::ffff:ffff
      denied-peer-ip=::ffff:0.0.0.0-::ffff:255.255.255.255
      denied-peer-ip=100::-100::ffff:ffff:ffff:ffff
      denied-peer-ip=2001::-2001:1ff:ffff:ffff:ffff:ffff:ffff:ffff
      denied-peer-ip=2002::-2002:ffff:ffff:ffff:ffff:ffff:ffff:ffff
      denied-peer-ip=fc00::-fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff
      denied-peer-ip=fe80::-febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff
    '';
    secure-stun = true;
    cert = config.age.secrets.fullchain.path;
    pkey = config.age.secrets.privkey.path;
    min-port = 49152;
    max-port = 49999;
  };

  # Open ports in the firewall.
  networking.firewall = {
    enable = true;
    allowPing = false;
    allowedTCPPorts = [
      5349  # STUN tls
      5350  # STUN tls alt
      80    # http
      443   # https
    ];
    allowedUDPPortRanges = [
      { from=49152; to=49999; } # TURN relay
    ];
  };

  
  
  services.matrix-synapse.settings = with config.services.coturn; {
     turn_uris = [
      "turn:${realm}:5349?transport=udp"
      "turn:${realm}:5350?transport=udp"
      "turn:${realm}:5349?transport=tcp"
      "turn:${realm}:5350?transport=tcp"
    ];
    turn_shared_secret = static-auth-secret;
#    extraConfigFiles = [ 
#      "${toString config.age.secrets.coturn.path}"
#    ];
    turn_user_lifetime = "1h";
  };
}
