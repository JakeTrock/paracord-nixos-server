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
    ./tailscale.nix
    ./coturn.nix
    ./synapse.nix
    ./monitoring.nix
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
      "ssh-ed25519 [SSH FINGERPRINT]"
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
     /* trashtoken = {
        file = /root/secrets/trashtoken.age;
        mode = "550";
        owner = "matrix-trashman";
      };*/
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
    pkgs.nur.repos.linyinfeng.synapse-s3-storage-provider
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

  services.openntpd = {#it's important to keep your NTP in sync when working with databases, websockets or real-time info transfers
    enable = true;
    servers = [
      "time.apple.com"
      "time.cloudflare.com"
      "pool.ntp.org"
    ];
  };

  system.stateVersion = "22.11";
}
