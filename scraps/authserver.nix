{ config, pkgs, ... }:
let 
  fqdn = "${config.networking.domain}";
in {
  services.mxisd = {
    enable = true;
    package = pkgs.ma1sd;
    matrix.domain = fqdn;
    server.name = fqdn;
    #https://github.com/ma1uta/ma1sd/tree/master/docs
    extraConfig = {
      synapseSql = {
  	enabled = true;
        type = "postgresql";
        connection = "//<[DATABASE ID].us-east-1.rds.amazonaws.com[:5432]/synapsedb?user=paracord&password=[LONG STRING PASSWORD]";
      };      
    };
  };
}

