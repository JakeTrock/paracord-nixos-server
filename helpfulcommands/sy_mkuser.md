https://nixos.org/manual/nixos/stable/index.html#module-services-matrix-register-users

nix-shell -p matrix-synapse

register_new_matrix_user -k your-registration-shared-secret http://localhost:8008
