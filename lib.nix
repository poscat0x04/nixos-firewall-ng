rec {
  # convert port and port ranges to nftables unamed set
  portsToUnamedSet = ports: portRanges:
    listToUnamedSet (
      map (p: builtins.toString p) ports ++
      map (pr: "${builtins.toString pr.from}-${builtins.toString pr.to}") portRanges
    );

  # convert a nonempty list of string to a nftables unamed set
  listToUnamedSet = l:
    let
      inner = builtins.concatStringsSep ", " l;
    in
      "{ ${inner} }";

  # convert a list of string to a nftables element string used in named sets
  listToElements = l: if builtins.length l == 0 then "" else "elements = ${listToUnamedSet l}";

  # convert a list of string to a nftables device string used in flowtables
  listToDevices = l: if builtins.length l == 0 then "" else "devices = ${listToUnamedSet l}";
}
