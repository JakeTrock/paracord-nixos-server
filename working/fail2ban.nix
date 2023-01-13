#from: https://github.com/AnotherBrynAlt/NixosSynapse
{ config, pkgs, ... }:
let
  fullyQualifiedDomainName = "${config.networking.domain}";
in {
  environment.etc = {
    "fail2ban/filter.d/nginx-bruteforce.conf".text = ''
      [Definition]
      failregex = ^<HOST>.*GET.*(matrix/server|\.php|admin|wp\-).* HTTP/\d.\d\" 404.*$
    '';
    
    "fail2ban/filter.d/matrix-synapse-loginspam.conf".text = ''
      [Definition]
      failregex = .*::ffff:<HOST> * Received request: POST.*\n.*Got login request.*\n.*Attempted to login as.*
                  .*::ffff:<HOST> * Received request: POST.*\n.*Got login request.*\n.*Failed password login.*
      journalmatch = _SYSTEMD_UNIT=matrix-synapse.service
    '';
  };

  services.fail2ban = {
    enable = true;
    maxretry = 5;
    ignoreIP = [
      "127.0.0.0/8" 
      "10.0.0.0/8" 
      "172.16.0.0/12" 
      "192.168.0.0/16"
      "8.8.8.8"
    ];
    # needed to ban on IPv4 and IPv6 for all ports
    extraPackages = [pkgs.ipset];
    banaction = "iptables-ipset-proto6-allports";
    jails = {
    # max 6 failures in 600 seconds
    "nginx-spam" = ''
      enabled  = true
      filter   = nginx-bruteforce
      logpath = /var/log/nginx/access.log
      backend = auto
      maxretry = 6
      findtime = 600
    '';

    # max 4 failures in 600 seconds
    "postfix-bruteforce" = ''
      enabled = true
      filter = matrix-synapse-loginspam
      findtime = 600
      maxretry = 4
    '';

    };
  };
}

