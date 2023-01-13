# from https://nixos.org/manual/nixos/stable/index.html#module-services-matrix-synapse
{ pkgs, lib, config, ... }:
let
  domain = "${config.networking.domain}";
in {
  services.matrix-synapse = {
    enable = true;
    withJemalloc = true;
    plugins = [
      pkgs.nur.repos.linyinfeng.synapse-s3-storage-provider
    ];

    settings = {
      push.include_content = false; #this may annoy some users
      trusted_third_party_id_servers = [
        "${domain}"
      ];
      encryption_enabled_by_default_for_room_type = "all";
      max_upload_size = "50M";
      retention = {
          enabled = true;
          default_policy = {
            min_lifetime = "1d";
            max_lifetime = "90d";
          };

          allowed_lifetime_min = "30m";
          allowed_lifetime_max = "90d";

          #purge_jobs = [
          #  {
          #    shorted_max_lifetime = "1d";
          #    longest_max_lifetime = "7d";
          #    interval = "5m";
          #  }
          #  {
          #    shortest_max_lifetime = "7d";
          #    longest_max_lifetime = "90d";
          #    interval = "24h";
          #  }
          #];
      };
         database = {
           name =  "psycopg2";
           args = {
             user = "synapse";
             password = "[LONG STRING PASSWORD]"; #TODO: SECRETIZE, turn secret too
             database = "synapsedb";
             host = "[DATABASE ID].us-east-1.rds.amazonaws.com";
             port = 5432;
             cp_min = 5;
             cp_max = 10;
           };
         };
         media_storage_providers = [{
            module = "s3_storage_provider.S3StorageProviderBackend";
            store_local = true;
            store_remote = true;
            store_synchronous = true;
            config = {
              bucket = "[MEDIA BUCKET NAME]";
            };
         }];
      url_preview_enabled = true;
      url_preview_ip_range_blacklist = [
          "127.0.0.0/8"
          "10.0.0.0/8"
          "172.16.0.0/12"
          "192.168.0.0/16"
          "100.64.0.0/10"
          "169.254.0.0/16"
          "::1/128"
          "fe80::/64"
          "fc00::/7"
      ];
      /*url_preview_url_blacklist = [ #fixme
          {
            username = "*";
          }
          { netloc = "google.com"; }
          { netloc = "*.google.com"; }
          {
            netloc = "^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$";
          }
      ];*/
      max_spider_size = "10M";
      server_name = domain;
      enable_registration = true;
      registration_shared_secret = "[LONG SECRET STRING]";
      enable_registration_without_verification = true;
      tls_certificate_path = config.age.secrets.fullchain.path;
      tls_private_key_path = config.age.secrets.privkey.path;
      suppress_key_server_warning = true;
      experimental_features = {
        spaces_enabled = true;
        msc3827_enabled = true;
      };
      federation_domain_whitelist = []; #disable federation to mitigate risks
      listeners = [
      { port = 8008;
        bind_addresses = [ "::1" "127.0.0.1" ];
        type = "http";
        tls = false;
        x_forwarded = true;
        resources = [ {
          names = [ "client" "federation" ];
          compress = true;
        } ];
      }
      {
          port = 8448;
          bind_addresses = [ "::" "0.0.0.0" ];
          type = "http";
          tls = true;
          x_forwarded = false;
          resources = [
            {
              names = [ "client" "federation" ];
              compress = false;
            }
          ];
        }
    ];
  };
  };

  /*users.users.matrix-trashman = {
    isSystemUser = true;
    group = "matrix-trashman";
  };*/

  systemd.services.purge-old-media = {
    path = [pkgs.curl];
    description = "Purge unused media";
    #export MATRIX_TOKEN=$(cat ${config.age.secrets.trashtoken.path}) # TODO: GAH GET THIS TO WORK
    script = ''
      curl 'http://localhost:8008/_synapse/admin/v1/media/examplewebsite.com/delete?before_ts='$(date -d "3 months ago" +%s%3N)'&size_gt=0&keep_profiles=true' -X POST -H 'Accept: application/json' -H 'authorization: Bearer syt_YWRtaW4_fvJqPcBdQueRTwgccOgz_2zFaC3' -H 'content-type: application/json';
    '';

    serviceConfig = {
      Type = "oneshot";
      User = "nobody";
     # User = "matrix-trashman";
     # Group = "matrix-trashman";
    };
  };
  systemd.timers.purge-old-media = {
    description = "Purge unused media";
    after = [ "network.target" "matrix-synapse.service" ];
    requires = ["purge-old-media.service"];
    wantedBy = ["multi-user.target"];
    timerConfig = {
     # OnUnitInactiveSec = 300;
     # RandomizedDelaySec = 300;
     OnCalendar = "Sun 14:00:00";
     Unit = "purge-old-media.service";
    };
  };

}
