{ config, lib, pkgs, ... }:

let
  inherit (lib.lists) forEach last;

  cfg = config.networking.firewall;
  cfg-ng = config.networking.fwng;

  refuse = if cfg.rejectPackets then "rejected" else "dropped";

  interfaces = builtins.attrNames cfg.interfaces;

  cgroups = builtins.attrNames cfg-ng.cgroupMarks;
  slices = forEach cgroups (cg: last (builtins.split "/" cg));

  fw-lib = import ./lib.nix;

  serviceToSystemdConfig = s: lib.mapAttrs' (attrName: config: rec {
    name = "nftables-${attrName}";
    value = let
      cfg' = config.deviceMode;

      # systemd does escaping of interface names when generating .device units
      escapedIfaceName = builtins.replaceStrings ["-"] ["\\x2d"] cfg'.interface;
      devDep = lib.optional cfg'.enable "sys-subsystem-net-devices-${escapedIfaceName}.device";

      snat = cfg'.nat.snatTarget != null;
      snat66 = cfg'.nat66.snatTarget != null;

      setMark = cfg'.mark != null;

      upRulesExtra = lib.optionalString cfg'.enable ''
        ${lib.optionalString cfg'.offload ''
          table inet filter {
            flowtable f {
              devices = { ${cfg'.interface} }
            }
          }
        ''}

        ${lib.optionalString cfg'.trust ''
          table inet filter {
            set lan_if {
              type iface_index
              elements = { ${cfg'.interface} }
            }
          }
        ''}

        ${lib.optionalString setMark ''
          table inet marking {
            map iif_mark {
              type iface_index : mark
              elements = { ${cfg'.interface} : ${cfg'.mark} }
            }
          }
        ''}

        ${lib.optionalString cfg'.nat.masquerade ''
          table ip nat {
            set masquerade_if {
              type iface_index
              elements = { ${cfg'.interface} }
            }
          }
        ''}

        ${lib.optionalString snat ''
          table ip nat {
            map snat_if {
              type iface_index : ipv4_addr
              elements = { ${cfg'.interface} : ${cfg'.nat.snatTarget} }
            }
          }
        ''}

        ${lib.optionalString cfg'.nat66.masquerade ''
          table ip6 nat66 {
            set masquerade_if {
              type iface_index
              elements = { ${cfg'.interface} }
            }
          }
        ''}

        ${lib.optionalString snat66 ''
          table ip6 nat66 {
            map snat_if {
              type iface_index : ipv6_addr
              elements = { ${cfg'.interface} : ${cfg'.nat66.snatTarget} }
            }
          }
        ''}
      '';

      downRulesExtra = lib.optionalString cfg'.enable ''
        ${lib.optionalString cfg'.offload ''
          delete flowtable inet filter f { devices = { ${cfg'.interface} }; }
        ''}

        ${lib.optionalString setMark ''
          delete element inet marking iif_mark { ${cfg'.interface} }
        ''}

        ${lib.optionalString cfg'.nat.masquerade ''
          delete element ip nat masquerade_if { ${cfg'.interface} }
        ''}

        ${''
          delete element ip nat snat_if { ${cfg'.interface} }
        ''}

        ${lib.optionalString cfg'.nat66.masquerade ''
          delete element ip6 nat66 masquerade_if { ${cfg'.interface} }
        ''}

        ${lib.optionalString snat66 ''
          delete element ip6 nat66 snat_if { ${cfg'.interface} }
        ''}
      '';

      startScript = pkgs.writeScript "nftables-${name}-start" ''
        #! ${pkgs.nftables}/bin/nft -f
        ${config.upRules}
        ${upRulesExtra}
      '';

      reloadScript = pkgs.writeScript "nftables-${name}-reload" ''
        #! ${pkgs.nftables}/bin/nft -f
        ${downRulesExtra}
        ${config.reloadRules}

        ${config.upRules}
        ${upRulesExtra}
      '';

      stopScript = pkgs.writeScript "nftables-${name}-stop" ''
        #! ${pkgs.nftables}/bin/nft -f
        ${downRulesExtra}
        ${config.downRules}
      '';

    in {
      inherit (config) description;
      wantedBy = lib.optional config.autoStart "multi-user.target" ++ devDep ++ config.wantedBy;
      after = [ "nftables.service" ] ++ devDep ++ config.after;
      bindsTo = [ "nftables.service" ] ++ devDep ++ config.bindsTo;
      reloadTriggers = [ startScript reloadScript stopScript ];
      unitConfig.ReloadPropagatedFrom = [ "nftables.service" ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecStart = startScript;
        ExecReload = reloadScript;
        ExecStop = stopScript;
      };
    };
  }) s;

  nft-service-mod = { config, ... }: {
    options = with lib; {
      enable = mkOption {
        type = types.bool;
        default = true;
        description = ''
          Whether to enable this nftables service
        '';
      };

      autoStart = mkOption {
        type = types.bool;
        default = false;
        description = ''
          Whether to start this service automatically during boot
        '';
      };

      description = mkOption {
        type = types.nullOr types.str;
        description = ''
          Description of the service.
        '';
      };

      deviceMode = {
        enable = mkEnableOption ''
          Whether to enable device mode, which binds this service to an interface.
        '';

        interface = mkOption {
          type = types.str;
          description = ''
            Name of the interface to bind to.
          '';
        };

        trust = mkEnableOption ''
          Whether to trust this device
        '';

        offload = mkEnableOption ''
          Whether to add this device to the flowtable.
        '';

        mark = mkOption {
          type = types.nullOr types.str;
          default = null;
          description = ''
            The firewall mark of all traffic associated with connections coming
            from this interface. Useful for achieving symmetric routing.
          '';
        };

        nat = {
          masquerade = mkEnableOption ''
            Whether to enable IPv4 masquerading on this interface
            Mutually exclusive with snatTarget
          '';

          snatTarget = mkOption {
            type = types.nullOr types.str;
            default = null;
            description = ''
              IP address to snat to
              Mutually exclusive with masquerade
            '';
          };
        };

        nat66 = {
          masquerade = mkEnableOption ''
            Whether to enable IPv6 masquerading on this interface.
            Mutually exclusive with snatTarget
          '';

          snatTarget = mkOption {
            type = types.nullOr types.str;
            default = null;
            description = ''
              IP address to snat to
              Mutually exclusive with masquerade
            '';
          };
        };
      };

      upRules = mkOption {
        type = types.lines;
        default = "";
        description = ''
          The nftables rules for brining up the firewall.

          When starting the service, upRules are applied.
          When reload the service, reloadRules and upRules are applied sequentially.
          When stopping the service, downRules are applied.
        '';
      };

      reloadRules = mkOption {
        type = types.lines;
        default = config.downRules;
        description = ''
          The nftables rules for reloading the firewall. By default, this is the same
          as downRules

          When starting the service, upRules are applied.
          When reload the service, reloadRules and upRules are applied sequentially.
          When stopping the service, downRules are applied.
        '';
      };

      downRules = mkOption {
        type = types.lines;
        default = "";
        description = ''
          The nftables rules for brining down the firewall.

          When starting the service, upRules are applied.
          When reload the service, reloadRules and upRules are applied sequentially.
          When stopping the service, downRules are applied.
        '';
      };

      wantedBy = mkOption {
        type = types.listOf types.str;
        default = [];
        description = ''
          Additional "WantedBy="s for the systemd service
        '';
      };

      bindsTo = mkOption {
        type = types.listOf types.str;
        default = [];
        description = ''
          Additional "BindsTo="s for the systemd service
        '';
      };

      after = mkOption {
        type = types.listOf types.str;
        default = [];
        description = ''
          Additional "After="s for the systemd service
        '';
      };
    };
  };
in {
  options.networking.fwng = with lib; {
    enable = mkEnableOption "Enable nixos-firewall-ng";

    filterPollutedDNS = mkOption {
      type = types.bool;
      default = true;
      description = ''
        Whether to filter out polluted dns responses
      '';
    };

    flowtable = {
      enable = mkOption {
        type = types.bool;
        default = true;
        description = ''
          Whether to enable flowtable forwarding acceleration.
        '';
      };

      devices = mkOption {
        type = types.listOf types.str;
        default = [];
        description = ''
          The devices/interfaces to offload for
        '';
      };
    };

    cgroupMarks = mkOption {
      type = types.attrsOf types.str;
      default = {};
      description = ''
        The firewall mark to assign to the (level 2) cgroup
      '';
    };

    nat = {
      enable = mkOption {
        type = types.bool;
        default = false;
        description = ''
          Whether to enable IPv4 NAT table
        '';
      };

      masquerade = mkOption {
        type = types.listOf types.str;
        default = [];
        description = ''
          (Outgoing) interfaces to masquerade IPv4 traffic
        '';
      };

      masqueradeAll = mkOption {
        type = types.bool;
        default = false;
        description = ''
          Whether to masquerade on all interfaces
        '';
      };

      snatConfig = mkOption {
        type = types.attrsOf types.str;
        default = {};
        description = ''
          Interfaces to snat. The keys are interface names and the values
          are addresses
        '';
      };
    };

    nat66 = {
      enable = mkOption {
        type = types.bool;
        default = false;
        description = ''
          Whether to enable IPv6 NAT table
        '';
      };

      masquerade = mkOption {
        type = types.listOf types.str;
        default = [];
        description = ''
          (Outgoing) interfaces to masquerade IPv6 traffic
        '';
      };

      masqueradeAll = mkOption {
        type = types.bool;
        default = false;
        description = ''
          Whether to masquerade on all interfaces
        '';
      };

      snatConfig = mkOption {
        type = types.attrsOf types.str;
        default = {};
        description = ''
          Interfaces to snat. The keys are interface names and the values
          are addresses
        '';
      };
    };

    nftables-service = mkOption {
      type = types.attrsOf (types.submodule nft-service-mod);
      default = {};
      description = ''
        Additional nftables services.
      '';
    };
  };

  config = lib.mkIf cfg-ng.enable {
    networking = {
      firewall = {
        enable = false;
        trustedInterfaces = [ "lo" ];
      };
      nftables = {
        enable = true;
        checkRuleset = false;
        ruleset = ''
          table inet filter {
            set lan_if {
              comment "LAN zone interfaces"
              type iface_index
              ${fw-lib.listToElements cfg.trustedInterfaces}
            }

            set globally_accepted_tcp_ports {
              type inet_service; flags interval; auto-merge
              ${fw-lib.portsToElements cfg.allowedTCPPorts cfg.allowedTCPPortRanges}
            }

            set globally_accepted_udp_ports {
              type inet_service; flags interval; auto-merge
              ${fw-lib.portsToElements cfg.allowedUDPPorts cfg.allowedUDPPortRanges}
            }

            ${lib.concatStrings (forEach interfaces (interface: let
              if-cfg = cfg.interfaces.${interface};
            in ''
              set if_${interface}_accepted_tcp_ports {
                type inet_service; flags interval; auto-merge

                ${fw-lib.portsToElements if-cfg.allowedTCPPorts if-cfg.allowedTCPPortRanges}
              }

              set if_${interface}_accepted_udp_ports {
                type inet_service; flags interval; auto-merge

                ${fw-lib.portsToElements if-cfg.allowedUDPPorts if-cfg.allowedUDPPortRanges}
              }
            ''))}

            ${lib.optionalString cfg-ng.flowtable.enable ''
              flowtable f {
                hook ingress priority 0
                ${fw-lib.listToDevices cfg-ng.flowtable.devices}
                counter
              }
            ''}

            chain input {
              type filter hook input priority filter; policy drop;

              ${lib.optionalString cfg-ng.filterPollutedDNS ''
                ip saddr { 8.8.8.8, 8.8.4.4 } udp sport 53 @ih,80,16 == 0 drop comment "Drop polluted DNS packets"
                ip6 saddr { 2620:fe::fe:11, 2001:4860:4860::8844 } udp sport 53 @ih,80,16 == 0 drop comment "Drop polluted DNS packets"
              ''}

              ct state { established, related } accept comment "Allow established"

              iif @lan_if accept comment "Allow input from LAN"
              jump zone_wan_input comment "Filter input from WAN"
            }

            chain zone_wan_input {
              udp dport 68 accept comment "Allow DHCP renew"
              ${lib.optionalString cfg.allowPing ''
                icmp type echo-request accept comment "Allow ping"
              ''}

              tcp dport @globally_accepted_tcp_ports accept
              udp dport @globally_accepted_udp_ports accept

              ${lib.concatStrings (forEach interfaces (interface: ''
                iif ${interface} tcp dport @if_${interface}_accepted_tcp_ports accept
                iif ${interface} udp dport @if_${interface}_accepted_udp_ports accept
              ''))}

              ip6 saddr fc00::/6 ip6 daddr fc00::/6 udp dport 546 accept comment "Allow DHCPv6"
              ip6 saddr fe80::/10 icmpv6 type {
                mld-listener-query,
                mld-listener-report,
                mld-listener-done,
                mld-listener-reduction,
                mld2-listener-report,
              } accept comment "Allow MLD"
              icmpv6 type {
                echo-request,
                echo-reply,
                destination-unreachable,
                packet-too-big,
                time-exceeded,
                parameter-problem,
                nd-router-solicit,
                nd-router-advert,
                nd-neighbor-solicit,
                nd-neighbor-advert,
              } limit rate 1000/second accept comment "Allow ICMPv6"

              ct status dnat accept comment "Allow port forwards"

              ${lib.optionalString cfg.logRefusedConnections ''
                tcp flags & ( fin | syn | rst | ack ) == syn ct state new log level info prefix "firewall: ${refuse} incomming connection "
              ''}

              ${lib.optionalString (cfg.logRefusedPackets && !cfg.logRefusedUnicastsOnly) ''
                meta pkttype broadcast log level info prefix "firewall: ${refuse} incomming broadcast "
                meta pkttype multicast log level info prefix "firewall: ${refuse} incomming multicast "
              ''}

              ${lib.optionalString cfg.logRefusedPackets ''
                meta pkttype host log level info prefix "firewall: ${refuse} incomming packet "
              ''}

              ${lib.optionalString cfg.rejectPackets ''
                meta l4proto tcp reject with tcp reset comment "Reject TCP with TCP rst"
                reject with icmpx type port-unreachable comment "Reject others with ICMP port unreachable"
              ''}
            }

            chain forward {
              type filter hook forward priority filter; policy drop;

              ${lib.optionalString cfg-ng.flowtable.enable ''
                meta l4proto { tcp, udp } flow offload @f
              ''}

              iif @lan_if accept comment "Allow LAN to anywhere"
              jump zone_wan_forward comment "Filter WAN forwards"
            }

            chain zone_wan_forward {
              ct state { established, related } accept comment "Allow established"

              icmpv6 type {
                echo-request,
                echo-reply,
                destination-unreachable,
                packet-too-big,
                time-exceeded,
                parameter-problem,
              } limit rate 1000/second accept comment "Allow ICMPv6 Forward"

              meta l4proto esp accept comment "Allow IPSec ESP"
              udp dport 500 accept comment "Allow ISAKMP"
              ct status dnat accept comment "Allow port forwards"

              oif != @lan_if reject with icmpx type no-route comment "Reject incorrectly routed packets"

              ${lib.optionalString cfg.logRefusedPackets ''
                meta pkttype host log level info prefix "firewall: dropped forwarding packet "
              ''}
            }
          }

          table inet clamp_mss {
            comment "Table that sets TCP MSS based on PMTUD information, a.k.a. mss clamping"

            chain forward {
              type filter hook forward priority mangle; policy accept;

              tcp flags syn tcp option maxseg size set rt mtu
            }
          }

          table inet marking {
            comment "Table that sets firewall marks and conntrack marks"

            map iif_mark {
              type iface_index : mark
            }

            map cgroupv2_l2_mark {
              type cgroupsv2 : mark
              ${fw-lib.mapToElements cfg-ng.cgroupMarks}
            }

            chain output {
              type route hook output priority mangle; policy accept;

              meta mark set socket cgroupv2 level 2 map @cgroupv2_l2_mark accept
              ct mark != 0 meta mark set ct mark
            }

            chain prerouting {
              type filter hook prerouting priority mangle; policy accept;
              ct state new ct mark set iif map @iif_mark
              ct mark != 0 meta mark set ct mark
            }
          }

          ${lib.optionalString cfg-ng.nat.enable ''
            table ip nat {
              set masquerade_if {
                type iface_index
                ${fw-lib.listToElements cfg-ng.nat.masquerade}
              }

              map snat_if {
                type iface_index : ipv4_addr
                ${fw-lib.mapToElements cfg-ng.nat.snatConfig}
              }

              chain postrouting {
                type nat hook postrouting priority srcnat; policy accept;

                snat to oif map @snat_if

                ${if cfg-ng.nat.masqueradeAll then ''
                  masquerade
                '' else ''
                  oif @masquerade_if masquerade
                ''}
              }
            }
          ''}

          ${lib.optionalString cfg-ng.nat66.enable ''
            table ip6 nat66 {
              set masquerade_if {
                type iface_index
                ${fw-lib.listToElements cfg-ng.nat66.masquerade}
              }

              map snat_if {
                type iface_index : ipv6_addr
                ${fw-lib.mapToElements cfg-ng.nat66.snatConfig}
              }

              chain postrouting {
                type nat hook postrouting priority srcnat; policy accept;

                snat to oif map @snat_if

                ${if cfg-ng.nat66.masqueradeAll then ''
                  masquerade
                '' else ''
                  oif @masquerade_if masquerade
                ''}
              }
            }
          ''}

        '';
      };
    };
    systemd.services = serviceToSystemdConfig cfg-ng.nftables-service // {
      nftables = {
        after = slices;
        bindsTo = slices;
        reloadIfChanged = lib.mkForce false;
        serviceConfig.ExecReload = lib.mkForce [];
      };
    };
  };
}
