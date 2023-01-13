# from https://nixos.org/manual/nixos/stable/index.html#module-services-matrix-synapse
{ pkgs, lib, config, ... }:
let
 
in {
  services.postgresql.enable = true;
  services.postgresql.initialScript = pkgs.writeText "synapse-init.sql" ''
    CREATE ROLE "matrix-synapse" WITH LOGIN PASSWORD 'synapse';
    CREATE DATABASE "matrix-synapse" WITH OWNER "matrix-synapse"
      TEMPLATE template0
      LC_COLLATE = "C"
      LC_CTYPE = "C";
    CREATE ROLE "grafana-db" WITH LOGIN PASSWORD 'grafana';
    CREATE DATABASE "grafana-db" WITH OWNER "grafana-db"
      TEMPLATE template0
      LC_COLLATE = "C"
      LC_CTYPE = "C";
  ''; 

}
