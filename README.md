# paracord-nixos-server
A paranoid nixos matrix server with monitoring

This is _NOT_ exactly the configuration I had on the server, much of it was restructured so it could be used as a community resource, much of the secret parts were kept in agenix, but I reverted their secret-ification so you could see how it all interlocks. The working config is in /working while the non-funcitonal scraps are in /scraps

This configuration was meant to be run on a Nixos ec2 instance, connected to an s3 bucket for media and a postgres db for database-y stuff.
