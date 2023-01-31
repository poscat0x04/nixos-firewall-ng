{
  description = "An improved zone-based nftables firewall for NixOS that is suitable for both routers and PCs.";

  outputs =
    {...}:
    {
      nixosModules.nixos-firewall-ng = import ./.;
      lib = import ./lib.nix;
    };
}
