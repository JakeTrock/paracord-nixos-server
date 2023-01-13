{ config, ... }:

{
  services.nginx = {
    enable = true;
    recommendedTlsSettings = true;
    recommendedOptimisation = true;
    recommendedGzipSettings = true;


    


    /*virtualHosts."examplewebsite.com" = {
     # enableACME = true;
      forceSSL = true;
      sslCertificate = ./cert.pem;
      sslCertificateKey = ./privkey.pem;
      root = "/var/www/paracordhome";
    };

    virtualHosts."matrix.examplewebsite.com" = {
      enableACME = true;
      forceSSL = true;
      locations."/" = {
        proxyPass = "http://127.0.0.1:8008";
        proxyWebsockets = true;
      };
    };

    virtualHosts."auth.examplewebsite.com" = {
   #    enableACME = true;
       forceSSL = true;
       sslCertificate = ./cert.pem;
       sslCertificateKey = ./privkey.pem;
       locations."/" = {
         proxyPass = "http://127.0.0.1:3000";
         proxyWebsockets = true;
       };
    };*/


  };
 # security.acme.defaults.dnsProvider = "route53";
 # security.acme.acceptTerms = true;
 # security.acme.defaults.email = "kapnklepto@hotmail.com";
 # security.acme.defaults.credentialsFile = ./r53creds;
}
