{config, pkgs, lib, ...}: {
 virtualisation.oci-containers.backend = "docker";
virtualisation.oci-containers.containers = {
    rageshake = {
      image = "awesometechnologies/rageshake";
    };
};
}
