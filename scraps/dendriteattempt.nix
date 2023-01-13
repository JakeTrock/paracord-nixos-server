{ config, pkgs, ... }:
let 
  fqdn = "${config.networking.domain}";
in {
  services.mxisd = {
    enable = true;
    package = pkgs.ma1sd;
    matrix.domain = fqdn;
    server.name = fqdn;
    server.port = 8070;
    #https://github.com/ma1uta/ma1sd/tree/master/docs
    extraConfig = {
      sql = {
  	enabled = true;
        type = "postgresql";
        connection = "//<[DATABASE ID].us-east-1.rds.amazonaws.com[:5432]/userdb?user=dendrite&password=[LONG STRING PASSWORD]";
      };      
    };
  };
}

{ modulesPath, config, pkgs, ... }:

let
  my-python-packages = python-packages: with python-packages; [
    certbot
    certbot-dns-route53
  ]; 
  python-with-my-packages = pkgs.python3.withPackages my-python-packages;
in {
  imports = [
    "${modulesPath}/virtualisation/amazon-image.nix"
    "${builtins.fetchTarball "https://github.com/ryantm/agenix/archive/main.tar.gz"}/modules/age.nix"
    ./nginx.nix                            
    ./dendrite.nix
    ./media-repo.nix
    ./tailscale.nix
    ./coturn.nix
    ./monitoring.nix
    ./authserver.nix
    ./fail2ban.nix
  ];

  ec2.hvm = true;
  ec2.efi = true;

  users.extraUsers.kapn = {
    isNormalUser = true;
    home = "/home/kapn";
    extraGroups = [ 
      "wheel"
      "docker"
      "podman"
    ];
    openssh.authorizedKeys.keys = [
      "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINjf91qUZgeQVxgYeTzkGJ5+HBBnDWFBye/6TZJLu+Bb"
    ];
  };

  age = {
    # We're letting `agenix` know where the locations of the age files will be
    # in the server.
    secrets = {
      monit = {
        file = /root/secrets/monit.age;
        mode = "550";
        owner = "root";
      };
      coturn = {
        file = /root/secrets/coturn.age;
        mode = "555";
        owner = "turnserver";
      };
      fullchain = {
        file = /root/secrets/fullchain.age;
        mode = "755";
        owner = "nginx";
        group = "nginx";
      };
      privkey = {
        file = /root/secrets/privkey.age;
        mode = "755";
        owner = "nginx";
        group = "nginx";
      };
      matrixsigning = {
        file = /root/secrets/matrixsigning.age;
        mode = "555";
        owner = "root";
      };
    };

    # Private key of the SSH key pair. This is the other pair of what was supplied
    # in `secrets.nix`.
    #
    # This tells `agenix` where to look for the private key.
    identityPaths = [ "/etc/ssh/ssh_host_ed25519_key" ];
  };

  nixpkgs.config.packageOverrides = pkgs: {
    nur = import (builtins.fetchTarball "https://github.com/nix-community/NUR/archive/master.tar.gz") {
      inherit pkgs;
    };
  };
  
  environment.systemPackages = with pkgs; [ 
    (pkgs.callPackage "${builtins.fetchTarball "https://github.com/ryantm/agenix/archive/main.tar.gz"}/pkgs/agenix.nix" {})
    git
    tailscale
    nmap
    python-with-my-packages
    docker-client
    nur.repos.darkkirb.matrix-media-repo
  ];
  
  services.cron = {
    enable = true;
    systemCronJobs = [
      "0 0 * * SUN root test -x /usr/local/bin/certbot && perl -e 'sleep int(rand(86400))' && /usr/local/bin/certbot renew"
    ];
  };

  systemd.tmpfiles.rules = [
    "e /nix/var/log - - - 30d"
  ];

  nix.gc.automatic = true;
  nix.gc.dates = "4:20";

  programs.bash.shellAliases = {
    nrb = "sudo nixos-rebuild switch";
    update = "sudo nixos-rebuild switch --upgrade";
    x = "exit";
  };

  services.openssh = {
    passwordAuthentication = false;
    allowSFTP = false; # Don't set this if you need sftp
    kbdInteractiveAuthentication = false;
    extraConfig = ''
      AllowTcpForwarding yes
      X11Forwarding no
      AllowAgentForwarding no
      AllowStreamLocalForwarding no
      AuthenticationMethods publickey
    '';
  };

  nix.settings.allowed-users = [ "@wheel" ];

  services.openntpd = {
    enable = true;
    servers = [
      "time.apple.com"
      "time.cloudflare.com"
      "pool.ntp.org"
    ];
  };

  system.stateVersion = "22.11";
}
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

  
  
  services.dendrite.settings.client_api.turn = with config.services.coturn; {
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
# from: https://github.com/nyrina-ops/nyrina-configs/tree/0850ba95c41282c3d1bac6321de11b16f2b41515/matrix
{ config, lib, pkgs, ... }:

let
  server_name = "${config.networking.domain}";
in
  {
    services = {
      dendrite = {
        enable = true;

        #environmentFile = "/run/secrets/dendrite/environment_file";
        settings = {
          logging = [{
          type = "file";
          level = "debug";
          params = {
            path = "/tmp"; #"/var/log/dendrite";
          };
          }]; 
          global = {
            server_name = server_name;
            private_key = config.age.secrets.matrixsigning.path; #"/var/lib/dendrite/matrix_key.pem";

            dns_cache = {
              enabled = true;
              cache_size = 256; # TODO: this likely should be increased, was 4096
              cache_lifetime = "600s";
            };

            presence = { #hogs cpu
              enable_inbound = false;
              enable_outbound = false;
            };

            cache.max_size_estimated = "512mb"; # TODO: this likely should be increased, was 16gb
          };

          # 'msc2444': Peeking over federation - https://github.com/matrix-org/matrix-doc/pull/2444
          # 'msc2753': Peeking via /sync - https://github.com/matrix-org/matrix-doc/pull/2753
          # 'msc2836': Threading - https://github.com/matrix-org/matrix-doc/pull/2836
          # 'msc2946': Spaces Summary - https://github.com/matrix-org/matrix-doc/pull/2946
          # 'msc3827': Public room filtering - https://github.com/matrix-org/matrix-spec-proposals/pull/3827
          mscs.mscs = [
            "msc2836"
            "msc2946"
           # "msc3827"
          ];

          client_api = {
            registration_shared_secret = "butternutsquash";
            #registration_disabled = false; # open reg, no craptcha
          };
          database = { 
            connection_string = "postgres://dendrite:[LONG STRING PASSWORD]@[DATABASE ID].us-east-1.rds.amazonaws.com/dendrite";
            max_open_conns = 90;
            max_idle_conns = 5;
          };
        };
      };
    };

 
    environment.systemPackages = [
      (pkgs.writeShellScriptBin "new-matrix-user" ''
        set -e
        username="$1"
        if [[ -z "$username" ]]; then
          echo "usage: new-matrix-user <username>" >&2
          exit 1
        fi
        password="$(${pkgs.pwgen}/bin/pwgen -s 32 1)"
        ${pkgs.dendrite}/bin/create-account \
          --config /run/dendrite/dendrite.yaml \
          --url http://localhost:8008 \
          --username "$username" \
          --passwordstdin <<<"$password"
        printf 'password: %s' "$password"
      '')
    ];

}
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

#from: https://github.com/DarkKirb/nixos-config/blob/34323fb8738404a0f46bef6c2dd82013a81cf6f9/config/services/matrix-media-repo.nix
#and:https://github.com/nyrina-ops/nyrina-configs/blob/0850ba95c41282c3d1bac6321de11b16f2b41515/matrix/media-repo.nix
{
  system,
  config,
  pkgs,
  lib,
  ...
}: let
  server_name = config.services.dendrite.settings.global.server_name;
  config-yml = pkgs.writeText "matrix-media-repo.yaml" (lib.generators.toYAML {} {
    repo = {
      bindAddress = "127.0.0.1";
      port = 8228;
      #logDirectory = "-";
    };
    database.postgres = "postgres://dendrite:[LONG STRING PASSWORD]@[DATABASE ID].us-east-1.rds.amazonaws.com/mediarepo";
    homeservers = [
      {
        name = "${server_name}";
        csApi = "${server_name}";
      }
    ];
    admins = ["@kapn:${server_name}"];
    uploads = {
      maxBytes = 52428800; #50m
      reportedMaxBytes = 52428800;
      minBytes = 100;
    };
    downloads = {
      maxBytes = 52428800;
      numWorkers = 10;
      failureCacheMinutes = 5;
    };
    datastores = [{
      type = "s3";
      enabled = true;
      forKinds = ["all"];
      opts = {
        tempPath = "";
        #endpoint = ""; #TODO: you may need this
        #accessKeyId = "$ACCESS_KEY_ID";
        #accessSecret = "$ACCESS_SECRET";
        ssl = true;
        bucketName = "[MEDIA BUCKET NAME]";
      };
    }];
    urlPreviews = {
      enabled = true;
      numWorkers = 10;
      oEmbed = true;
      allowedNetworks = [
        "0.0.0.0/0"
        "::/0"
      ];
      disallowedNetworks = [
        "127.0.0.1/8"
        "10.0.0.0/8"
        "172.16.0.0/12"
        "192.168.0.0/16"
        "::1/128"
        "fe80::/64"
        "fc00::/7"
      ];
      userAgent = "TelegramBot (like TwitterBot)"; # to make it work with fxtwitter/vxtwitter
    };
    downloads = {
      expireAfterDays = 7;
    };
    featureSupport = {
      MSC2448.enabled = true;
      MSC2246 = {
        enabled = true;
        asyncUploadExpirySecs = 120;
      };
    };
    thumbnails = {
      maxSourceBytes = 0;
      maxPixels = 102000000;
      types = [
        "image/jpeg"
        "image/jpg"
        "image/png"
        "image/apng"
        "image/gif"
        "image/heif"
        "image/webp"
        "image/svg+xml"
        "image/jxl"
        "audio/mpeg"
        "audio/ogg"
        "audio/wav"
        "audio/flac"
        "video/mp4"
        "video/webm"
        "video/x-matroska"
        "video/quicktime"
      ];
    };
  });
in {
  systemd.services.matrix-media-repo = {
    description = "Matrix Media Repo";
    after = ["network.target"];
    wantedBy = ["multi-user.target"];
    path = [pkgs.nur.repos.darkkirb.matrix-media-repo pkgs.ffmpeg pkgs.imagemagick];
    /*preStart = ''
      akid=$(cat ${config.sops.secrets."services/matrix-media-repo/access-key-id".path})
      sak=$(cat ${config.sops.secrets."services/matrix-media-repo/secret-access-key".path})
      cat ${config-yml} > /var/lib/matrix-media-repo/config.yml
      sed -i "s|#ACCESS_KEY_ID#|$akid|g" /var/lib/matrix-media-repo/config.yml
      sed -i "s|#SECRET_ACCESS_KEY#|$sak|g" /var/lib/matrix-media-repo/config.yml
    '';*/
    preStart = ''
      cat ${config-yml} > /var/lib/matrix-media-repo/config.yml
    '';
    serviceConfig = {
      Type = "simple";
      User = "matrix-media-repo";
      Group = "matrix-media-repo";
      Restart = "always";
      ExecStart = "${pkgs.nur.repos.darkkirb.matrix-media-repo}/bin/media_repo -config /var/lib/matrix-media-repo/config.yml";
    };
  };
  /*systemd.services.purge-old-media = {
    path = [pkgs.curl];
    description = "Purge unused media";
    script = ''
      export MATRIX_TOKEN=$(cat ${config.sops.secrets."services/matrix-media-repo/matrix-token".path})
      for i in $(seq 1000); do
        curl -H "Authorization: Bearer $MATRIX_TOKEN" -X POST https://matrix.chir.rs/_matrix/media/unstable/admin/purge/old\?before_ts=$(date -d "3 months ago" +%s%3N)\&include_local=true && exit 0
      done
    '';

    serviceConfig = {
      Type = "oneshot";
      User = "matrix-media-repo";
      Group = "matrix-media-repo";
    };
  };
  systemd.timers.purge-old-media = {
    description = "Purge unused media";
    after = ["network.target" "matrix-media-repo.service"];
    requires = ["purge-old-media.service"];
    wantedBy = ["multi-user.target"];
    timerConfig = {
      OnUnitInactiveSec = 300;
      RandomizedDelaySec = 300;
    };
  };*/
  #sops.secrets."services/matrix-media-repo/access-key-id".owner = "matrix-media-repo";
  #sops.secrets."services/matrix-media-repo/secret-access-key".owner = "matrix-media-repo";
  #sops.secrets."services/matrix-media-repo/matrix-token".owner = "matrix-media-repo";
  users.users.matrix-media-repo = {
    description = "Matrix Media Repository";
    home = "/var/lib/matrix-media-repo";
    useDefaultShell = true;
    group = "matrix-media-repo";
    isSystemUser = true;
  };
  users.groups.matrix-media-repo = {};
  systemd.tmpfiles.rules = [
    "d '/var/lib/matrix-media-repo' 0750 matrix-media-repo matrix-media-repo - -"
  ];
  services.nginx.virtualHosts."${server_name}".locations."/_matrix/media".proxyPass = "http://127.0.0.1:8228";

}
{ pkgs, lib, config, ... }:
let
 
in {
  services.monit.enable = true;
  # https://mmonit.com/monit/documentation/monit.html   
  #TODO: PUT IN SECRETFIL
  services.monit.config = ''
    set alert your@email.com
    set httpd
     port 2812         
     use address 127.0.0.1
     allow kapn:icarusSUN9960
    set daemon 1800
     with start delay 20

    #netwurk
    check host pcdLocal with address 0.0.0.0
     if failed port 8008 protocol http then alert
     if failed port 80 protocol http then alert
     every 5 cycles

    check host pcdForeign with address examplewebsite.com
     if failed port 443 protocol https then alert
     if failed port 80 protocol http then alert
     every 5 cycles

    check host pcdDb with address examplewebsite.com
     if failed host [DATABASE ID].us-east-1.rds.amazonaws.com port 5432 protocol pgsql username "dendrite" password "[LONG STRING PASSWORD]" database "dendrite" type TCP then alert
     every 50 cycles

    #systemd

    check process nginx with pidfile /run/nginx/nginx.pid
     if failed port 443 protocol https then alert
     if failed port 80 protocol http then alert
     every 5 cycles

    check process coturn with pidfile /run/turnserver/turnserver.pid

    check process ntpd with pidfile /run/openntpd.pid
     every 5 cycles

    check process dendrite matching "dendrite"
     if failed port 8008 protocol http then alert

    check process tailscale matching "tailscale"
     every 5 cycles

    #system
    check system $HOST
     if loadavg (5min) > 3 then alert
     if loadavg (15min) > 1 then alert
     if memory usage > 80% for 4 cycles then alert
     if swap usage > 20% for 4 cycles then alert
     # Test the user part of CPU usage 
     if cpu usage (user) > 80% for 2 cycles then alert
     # Test the system part of CPU usage 
     if cpu usage (system) > 20% for 2 cycles then alert
     # Test the i/o wait part of CPU usage 
     if cpu usage (wait) > 80% for 2 cycles then alert
     # Test CPU usage including user, system and wait. Note that 
     # multi-core systems can generate 100% per core
     # so total CPU usage can be more than 100%
     if cpu usage > 200% for 4 cycles then alert
     every 3 cycles

    check device main with path /
     if SPACE usage > 80% then alert
  '';
}
#docs: https://docs.t2bot.io/matrix-media-repo/configuration/logging.html
#from: https://github.com/nyrina-ops/nyrina-configs/blob/0850ba95c41282c3d1bac6321de11b16f2b41515/matrix/media-repo.nix
{ config, ... }:

let
  server_name = config.services.dendrite.settings.global.server_name;
in
  {
    services = {
      matrix-media-repo = {
        enable = true;
        #environmentFile = "/run/secrets/matrix-media-repo/environment_file"; TODO: use this to pass in $SECRET from cli https://github.com/matrix-org/synapse/issues/7758
        settings = {
          homeservers = [
            {
              name = server_name;
              csApi = "https://${server_name}/";
            }
          ];
          uploads = {
            maxBytes = 52428800; #50m
            reportedMaxBytes = 52428800;
            minBytes = 100;
          };
          downloads = {
            maxBytes = 52428800;
            numWorkers = 10;
            failureCacheMinutes = 5;
            expireAfterDays = 0;
          };
          database.postgres = "postgres://dendrite:[LONG STRING PASSWORD]@[DATABASE ID].us-east-1.rds.amazonaws.com/mediarepo";
          datastores = [
            {
              type = "s3";
              opts = {
                tempPath = "";
                #endpoint = ""; #TODO: you may need this
                #accessKeyId = "$ACCESS_KEY_ID";
                #accessSecret = "$ACCESS_SECRET";
                ssl = true;
                bucketName = "[MEDIA BUCKET NAME]";
              };
            }
          ];
          # "defaults" aren't actually properly default... remove this at some point?
          # https://github.com/turt2live/matrix-media-repo/blob/bfb7d8d7399252b0bf1428c6429a4d16b17f2224/common/config/conf_domain.go#L68-L71
          thumbnails.types = [
            "image/jpeg"
            "image/jpg"
            "image/png"
            "image/apng"
            "image/gif"
            "image/heif"
            "image/webp"
            #"image/svg+xml" # Be sure to have ImageMagick installed to thumbnail SVG files
            "audio/mpeg"
            "audio/ogg"
            "audio/wav"
            "audio/flac"
            #"video/mp4" # Be sure to have ffmpeg installed to thumbnail video files
          ];
        };
      };

      nginx.virtualHosts."${server_name}".locations."/_matrix/media".proxyPass = "http://127.0.0.1:8000";
    };

    #sops.secrets."matrix-media-repo/environment_file" = {};
  }
#from: https://github.com/AnotherBrynAlt/NixosSynapse
{ config, pkgs, ... }:
let
  fullyQualifiedDomainName = "examplewebsite.com";
  clientConfig = {
    "m.homeserver".base_url = "https://${fullyQualifiedDomainName}";
    "m.homeserver".server_name = "examplewebsite.com";
    "m.identity_server".base_url = "https://examplewebsite.com";
    "io.element.e2ee" = {
        "default" = true;
    };
  };
  serverConfig = {
    "m.server" = "${fullyQualifiedDomainName}:443";
  };
  mkWellKnown = serverData: ''
    add_header Content-Type application/json;
    add_header Access-Control-Allow-Origin *;
    return 200 '${builtins.toJSON serverData}';
  '';
in {
  networking.domain = fullyQualifiedDomainName;
  networking.firewall.allowedTCPPorts = [ 80 443 8008 8448];

  services.nginx = {
    enable = true;
    virtualHosts = {
      "${fullyQualifiedDomainName}" = {
        forceSSL = true;
        sslCertificate = config.age.secrets.fullchain.path;
        sslCertificateKey = config.age.secrets.privkey.path;
        extraConfig = ''
          keepalive_requests 10000;
        '';
        #locations."~* ^(/_matrix|/_synapse/client)" = {
        #  proxyPass = "http://[::1]:8008"; # without a trailing /
        #};
        locations = {
          #"/".proxyPass = "http://[::1]:8080"; #TODO:paracord nodeport
          "/_matrix".proxyPass = "http://[::1]:${toString config.services.dendrite.httpPort}";
          "/_synapse".proxyPass = "http://[::1]:${toString config.services.dendrite.httpPort}";
          "/_matrix/identity".proxyPass = "http://[::1]:8070/_matrix/identity";
          "/_matrix/client/r0/login".proxyPass = "http://[::1]:8070";
          "/admin".root = pkgs.linkFarm "synapse-admin-routing" [{
            name = "admin";
            path = "${pkgs.synapse-admin}";
          }];
          "= /.well-known/matrix/server".extraConfig = mkWellKnown serverConfig;
          "= /.well-known/matrix/client".extraConfig = mkWellKnown clientConfig;
        };
        #locations."/" = {
        #  root = indexHtml;
        #};
      };

     "monitoring.${fullyQualifiedDomainName}" = {
        forceSSL = true;
        sslCertificate = config.age.secrets.fullchain.path;
        sslCertificateKey = config.age.secrets.privkey.path;
        locations."/" = {
          proxyPass = "http://127.0.0.1:2812/";
          proxyWebsockets = true;
        };
      };

      "matrix.${fullyQualifiedDomainName}" = {
        forceSSL = true;
        sslCertificate = config.age.secrets.fullchain.path;
        sslCertificateKey = config.age.secrets.privkey.path;
        serverAliases = [ "matrix.${config.networking.domain}" ];

        root = pkgs.element-web.override {
          conf = {
            default_server_config = clientConfig;
          };
        };
      };

      "turn.${fullyQualifiedDomainName}" = {
        sslCertificate = config.age.secrets.fullchain.path;
        sslCertificateKey = config.age.secrets.privkey.path;
        forceSSL = true;
      };

    };

    recommendedGzipSettings = true;
    recommendedOptimisation = true;
    recommendedProxySettings = true;
    recommendedTlsSettings = true;
    clientMaxBodySize = "100m";
  };
}

{ pkgs, lib, config, ... }:
let
 tskey = "[TAILSCALE KEY]";
in {
  services.tailscale.enable = true;

  systemd.services.tailscale-autoconnect = {
    description = "Automatic connection to Tailscale";

    # make sure tailscale is running before trying to connect to tailscale
    after = [ "network-pre.target" "tailscale.service" ];
    wants = [ "network-pre.target" "tailscale.service" ];
    wantedBy = [ "multi-user.target" ];

    # set this service as a oneshot job
    serviceConfig.Type = "oneshot";

    # have the job run this shell script
    script = with pkgs; ''
      # wait for tailscaled to settle
      sleep 2

      # check if we are already authenticated to tailscale
      status="$(${tailscale}/bin/tailscale status -json | ${jq}/bin/jq -r .BackendState)"
      if [ $status = "Running" ]; then # if so, then do nothing
        exit 0
      fi

      # otherwise authenticate with tailscale
      ${tailscale}/bin/tailscale up -authkey ${tskey}
    '';
  };

  networking.firewall = {
    checkReversePath = "loose";   

    # always allow traffic from your Tailscale network
    trustedInterfaces = [ "tailscale0" ];

    # allow the Tailscale UDP port through the firewall
    allowedUDPPorts = [ config.services.tailscale.port ];
  };

}
