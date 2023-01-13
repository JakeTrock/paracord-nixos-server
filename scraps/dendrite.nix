{ config, ... }:

let
  httpPort = 80;
  dendriteServerName = "examplewebsite.com";
  connectionString = "postgres://dendrite:dendrite@127.0.0.1/dendrite?sslmode=disable";
  federationPort = 8448;
in
{
  services.dendrite = {
    enable = true;
    httpsPort = 8448;
    tlsCert = ./cert.pem;
    tlsKey = ./privkey.pem;
    
    
    settings = {
      app_service_api.database.connection_string = connectionString;
      federation_api.database.connection_string = connectionString;
      key_server.database.connection_string = connectionString;
      media_api.database.connection_string = connectionString;
      mscs.database.connection_string = connectionString;
   #   room_server.database.connection_string = connectionString;
    #  sync_api.database.connection_string = connectionString;
     # sync_api.search.enable = true;
     # user_api.account_database.connection_string = connectionString;
     # user_api.device_database.connection_string = connectionString;

      client_api.registration_disabled = true;

      # 2 megabytes in bytes
      media_api.max_file_size_bytes = 2097152;

      mscs.mscs = [
        # threading
        "msc2946"
        # spaces
        "msc2836"
      ];

      federation_api = {
        external_api = {
          listen = "http://localhost:${toString federationPort}";
        };
      };

      global = {
       /* metrics.enabled = true;*/
        server_name = "${dendriteServerName}";
        private_key = ./matrix_key.pem;
      };
    };
  };

  networking.firewall.allowedTCPPorts = [ 80 443 8008 8448 ];

  /*services.prometheus.scrapeConfigs = [
    {
      job_name = "dendrite";
      static_configs = [{
        targets = [
          "127.0.0.1:${toString httpPort}"
        ];
      }];
    }
  ];*/
}
