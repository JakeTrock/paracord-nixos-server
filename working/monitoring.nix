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
     if failed host [DATABASE ID].us-east-1.rds.amazonaws.com port 5432 protocol pgsql username "paracord" password "[LONG STRING PASSWORD]" database "synapsedb" type TCP then alert
     every 50 cycles

    #systemd

    check process nginx with pidfile /run/nginx/nginx.pid
     if failed port 443 protocol https then alert
     if failed port 80 protocol http then alert
     every 5 cycles

    check process coturn with pidfile /run/turnserver/turnserver.pid

    check process ntpd with pidfile /run/openntpd.pid
     every 5 cycles

    check process dendrite matching "synapse"
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
