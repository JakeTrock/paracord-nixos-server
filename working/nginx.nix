#from: https://github.com/AnotherBrynAlt/NixosSynapse
{ config, pkgs, ... }:
let
  fullyQualifiedDomainName = "examplewebsite.com";
  clientConfig = {
    "m.homeserver".base_url = "https://${fullyQualifiedDomainName}";
    "m.homeserver".server_name = "examplewebsite.com";
    "m.identity_server".base_url = ""; #disable it!
    "io.element.e2ee" = {
      "default" = true;
      "secure_backup_required" = true;
      "secure_backup_setup_methods" = [ 
        "passphrase"
       # "key"
      ];
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
        locations = {
          "/" = {
            index = "index.html index.htm";
            root = "/var/www/htmlhome/";
          };
          "/_matrix" = {
            proxyPass = "http://[::1]:8008"; 
            proxyWebsockets = true;
          };
          "/_synapse/client" = {
            proxyPass = "http://[::1]:8008"; 
            proxyWebsockets = true;
          };
          #remove later
          "/_synapse/admin" = {
            proxyPass = "http://[::1]:8008"; 
            proxyWebsockets = true;
          };
          "/admin".root = pkgs.linkFarm "synapse-admin-routing" [{
            name = "admin";
            path = "${pkgs.synapse-admin}";
          }];
          #remove later

          "= /.well-known/matrix/server".extraConfig = mkWellKnown serverConfig;
          "= /.well-known/matrix/client".extraConfig = mkWellKnown clientConfig;
        };
        #locations."/" = {
        #  root = indexHtml;
        #};
      };

     "monitoring.${fullyQualifiedDomainName}" = { #TODO: this should only be accessible on the tailnet
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

