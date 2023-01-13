{config, pkgs, lib, ...}:
let

in {
  services.prometheus = {
    enable = true;

    exporters = {
      node = {
        enable = true;
        enabledCollectors = [ "systemd" ];
        port = 9003;
      };
    };

    scrapeConfigs = [{
      job_name = "synapse";
      scrape_interval = "10s";
      metrics_path = "/_synapse/metrics";
      static_configs = [{
        targets = [
          "localhost:9002"
          "localhost:9003"
         ];
        labels = { alias = "prometheus.synapse.${config.networking.domain}"; };
      }];
    }
    {
        job_name = "systemd";
        static_configs = [{
          targets = [ "127.0.0.1:${toString config.services.prometheus.exporters.node.port}" ];
        }];
      }
    ];
  };

  services.grafana = {
    enable = true;

    settings = {
      server.http_addr = "127.0.0.1";
      security.admin_password = "icarusSUN9960";
      server.domain = "grafana.${config.networking.domain}";
      database = {
        type = "postgres";
        host = "127.0.0.1";
        user = "grafana-db";
        name = "grafana-db";
        password = "grafana";
      };
    };

    provision = {
      enable = true;

      dashboards.settings = let
        d = name: path: { inherit name path; };
        f = name: url: sha256: d name (pkgs.fetchurl { inherit url sha256; });
      in {
        apiVersion = 1;
        providers = map (x: {
          name = x.name;
          type = "file";
          folder = "Server";
          options.path = x.path;
        }) [

          (f "synapse"
            "https://raw.githubusercontent.com/matrix-org/synapse/develop/contrib/grafana/synapse.json"
            "sha256-TUusGvfy9PZoIalY5oVzzTYBA4WO58vemkZ6rtPMyJ0=")

        ];
      };

      datasources.settings = {
        apiVersion = 1;
        datasources = [
          {
            name = "Prometheus";
            type = "prometheus";
            url = "http://127.0.0.1:${toString config.services.prometheus.port}";
            access = "proxy";
            isDefault = true;
            jsonData = {
              timeInterval = config.services.prometheus.globalConfig.scrape_interval;
            };
          }
        ];
      };
    };

  };
}
