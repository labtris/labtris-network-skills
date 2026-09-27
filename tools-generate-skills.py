"""Emit packet_analysis skills. Fields here are verified against tshark 4.2.2."""
import pathlib, sys

P = {}
def sk(key, name, desc, filt, fields, checks, legacy=False):
    P[key] = dict(name=name, description=desc, display_filter=filt,
                  fields=fields, checks=checks, legacy=legacy)

F = lambda l, f, d: (l, f, d)
C = lambda n, w, m, x: dict(name=n, when=w, means=m, next=x)

FRAME = F("Frame Number", "frame.number", "Position in the capture")
SRC   = F("Source", "ip.src", "Sending address")
DST   = F("Destination", "ip.dst", "Receiving address")
ESRC  = F("Source MAC", "eth.src", "Sending interface")

sk("arp", "ARP resolution",
   "Whether a host can turn an IP address into a MAC address. Most 'no connectivity' on a working L2 segment stops here.",
   "arp",
   [FRAME, F("Opcode","arp.opcode","1 request, 2 reply"),
    F("Sender MAC","arp.src.hw_mac","Who is answering"),
    F("Sender IP","arp.src.proto_ipv4","The address being claimed"),
    F("Target IP","arp.dst.proto_ipv4","The address being asked about"),
    F("Duplicate detected","arp.duplicate-address-detected","Wireshark flags two MACs claiming one IP")],
   [C("requests-no-replies","requests repeat with no opcode 2",
      "The target is not on this segment, is down, or its replies are not coming back this way.",
      "Capture on the target's own interface — a reply that is sent but not received is a different fault"),
    C("duplicate-address","arp.duplicate-address-detected is set",
      "Two hosts claim the same IP. Traffic will follow whichever answered last and flap.",
      "Find both MACs and fix the addressing; this is not a routing problem"),
    C("gratuitous-flood","repeated unsolicited replies for the same IP",
      "Something is announcing itself hard — a failover, or a misconfigured VRRP/HSRP pair.",
      "Check the first-hop redundancy protocol before suspecting a host")])

sk("dhcp", "DHCP address assignment",
   "Why a client does not get an address, or gets the wrong one. Read the four-message exchange in order.",
   "dhcp",
   [FRAME, F("Message Type","dhcp.option.dhcp","1 DISCOVER, 2 OFFER, 3 REQUEST, 5 ACK, 6 NAK"),
    F("Client MAC","dhcp.hw.mac_addr","Which client"),
    F("Your IP","dhcp.ip.your","The address being offered or confirmed"),
    F("Requested IP","dhcp.option.requested_ip_address","What the client asked to keep"),
    F("Server ID","dhcp.option.dhcp_server_id","Which server answered")],
   [C("discover-no-offer","DISCOVER repeats with no OFFER",
      "No server heard it, or none has a free lease. DHCP is broadcast, so a missing relay on a routed segment looks exactly like a dead server.",
      "Check for a relay/helper on the client's gateway before looking at the server"),
    C("nak-after-request","REQUEST answered with NAK",
      "The client asked to keep an address the server will not honour — usually a stale lease from another subnet.",
      "Have the client release and rediscover"),
    C("two-server-ids","OFFERs carry different dhcp.option.dhcp_server_id",
      "Two servers are answering. The client takes the first, which may not be the one you configured.",
      "Find the second server; in a lab it is often a NAT segment's own dnsmasq")])

sk("dns", "DNS resolution",
   "Whether name resolution works, and if not, whether the failure is the query, the server or the answer.",
   "dns",
   [FRAME, SRC, DST, F("Query Name","dns.qry.name","What was asked for"),
    F("Query Type","dns.qry.type","1 A, 28 AAAA, 12 PTR, 15 MX"),
    F("Response Code","dns.flags.rcode","0 NOERROR, 2 SERVFAIL, 3 NXDOMAIN"),
    F("Answer","dns.a","The address returned, if any")],
   [C("query-no-response","queries repeat with no reply",
      "The resolver is unreachable, or UDP 53 is being dropped in one direction.",
      "Check reachability to the resolver address itself before blaming DNS"),
    C("servfail","rcode is 2",
      "The resolver tried and failed upstream — not the client's fault.",
      "Test the same query directly against the upstream the resolver uses"),
    C("nxdomain-for-a-name-that-exists","rcode is 3 for a name you expect to resolve",
      "Wrong search domain, or the client is asking a resolver that does not host the zone.",
      "Compare the fully qualified name in dns.qry.name against what was typed")])

sk("icmp", "ICMP",
   "What the network is telling you about a failure. ICMP is usually the answer rather than the problem.",
   "icmp",
   [FRAME, SRC, DST, F("Type","icmp.type","0 echo reply, 3 unreachable, 8 echo request, 11 time exceeded"),
    F("Code","icmp.code","Qualifies the type — for type 3, 0 net, 1 host, 3 port, 4 frag needed"),
    F("Sequence","icmp.seq","Pairs a request with its reply"),
    F("TTL","ip.ttl","How many hops were left")],
   [C("unreachable-from-a-router","type 3 from an address that is not the destination",
      "A router on the path is rejecting it. The code says why, and the source says where.",
      "Read icmp.code; type 3 code 4 means an MTU problem, not a routing one"),
    C("time-exceeded","type 11",
      "TTL ran out — a routing loop, or simply a traceroute in progress.",
      "If it is not a traceroute, look for a loop between the two routers that keep appearing"),
    C("requests-without-replies","type 8 with no matching type 0",
      "The destination is not responding. It may be down, filtered, or the return path may be broken.",
      "Capture at the destination: a request that arrives and is not answered is a host problem, not a network one")])

sk("stp", "Spanning Tree",
   "Which switch is root, which ports are blocking, and whether the topology is still converging.",
   "stp",
   [FRAME, ESRC, F("BPDU Type","stp.type","0 configuration, 128 TCN"),
    F("Root Bridge","stp.root.hw","Who the sender believes is root"),
    F("Sending Bridge","stp.bridge.hw","Who sent this BPDU"),
    F("Flags","stp.flags","Topology change and topology change acknowledgement bits"),
    F("Port","stp.port","Sending port identifier")],
   [C("root-changing","stp.root.hw is not stable across the capture",
      "The root is being re-elected, so the whole topology is reconverging and traffic is disrupted.",
      "Find the switch with the lowest priority that keeps appearing and decide whether it should be root"),
    C("tcn-storm","repeated TCN BPDUs",
      "Something keeps flapping. Each change flushes MAC tables, which looks like intermittent loss everywhere.",
      "Find the flapping port; an access port without portfast is the usual cause"),
    C("no-bpdus","no BPDUs on a link you expect them on",
      "STP is disabled, filtered, or the link is not actually carrying the VLAN.",
      "On a Labtris bridge this is expected — see the note in this file's description")])

sk("lldp", "LLDP neighbour discovery",
   "What a device says it is and which port you are plugged into. The fastest way to confirm cabling matches the diagram.",
   "lldp",
   [FRAME, ESRC, F("System Name","lldp.tlv.system.name","The neighbour's hostname"),
    F("System Description","lldp.tlv.system.desc","Platform and version string"),
    F("Chassis ID","lldp.chassis.id","Identifies the device"),
    F("Port ID","lldp.port.id","Which of its ports this came from")],
   [C("no-lldp-at-all","no frames on a link where both ends should advertise",
      "LLDP is off on one end, or a bridge in between is consuming the frames. LLDP uses a reserved multicast address that Linux bridges swallow by default.",
      "Labtris forwards this range deliberately; on other emulators check the bridge's group_fwd_mask"),
    C("one-way","frames from one end only",
      "The quiet end has LLDP receive-only or disabled.",
      "Enable transmit on the quiet device"),
    C("wrong-neighbour","system name is not the device the diagram expects",
      "The cabling does not match the drawing.",
      "Trust the capture over the diagram")])

sk("lacp", "LACP link aggregation",
   "Whether two ends agree to bundle links, and if not, which side is refusing.",
   "lacp",
   [FRAME, ESRC, F("Actor System ID","lacp.actor.sysid","Who the sender is"),
    F("Actor Key","lacp.actor.key","Bundle identity — must match across members on one side"),
    F("Actor State","lacp.actor.state","Activity, timeout, aggregation, synchronisation bits"),
    F("Partner State","lacp.partner.state","What the sender believes about the far end")],
   [C("never-synchronised","actor state never shows synchronisation",
      "The two ends disagree — different keys, or one side is passive and so is the other.",
      "At least one end must be active; compare lacp.actor.key across the members"),
    C("partner-unknown","partner fields stay at defaults",
      "The sender is not hearing the far end at all.",
      "Check the link carries LACP frames in both directions before touching bundle config"),
    C("flapping-bundle","actor state oscillates",
      "Members are joining and leaving — often a speed or duplex mismatch on one member.",
      "Compare the members; a bundle is only as consistent as its worst link")])

sk("vlan", "802.1Q VLAN tagging",
   "Whether a frame is tagged, with which VLAN, and at which priority. Priority matters on a lab with per-class queueing.",
   "vlan",
   [FRAME, ESRC, F("VLAN ID","vlan.id","1-4094; 1 is usually the untagged default"),
    F("Priority","vlan.priority","802.1p PCP — the class a PFC-enabled link queues on"),
    F("Encapsulated type","vlan.etype","What is inside the tag")],
   [C("untagged-where-tagged-expected","no vlan.id on a trunk",
      "The frame is on the native VLAN, or the port is an access port.",
      "Native-VLAN mismatch between two trunks silently merges two broadcast domains — check both ends"),
    C("all-priority-zero","vlan.priority is 0 on traffic meant to be prioritised",
      "Nothing is marking the traffic, so per-priority queueing has nothing to act on.",
      "Mark at the source; the queue cannot classify what is not marked"),
    C("unexpected-vlan","a VLAN ID that is not in the design",
      "A trunk is allowing more than it should.",
      "Prune the allowed list")])


sk("tcp", "TCP behaviour",
   "Whether a connection establishes, stays healthy, and who is limiting it. Retransmissions and zero windows separate a network problem from an endpoint one.",
   "tcp",
   [FRAME, SRC, DST, F("Stream","tcp.stream","Groups packets into one connection"),
    F("SYN","tcp.flags.syn","Connection setup"),
    F("Reset","tcp.flags.reset","Abrupt close — someone refused or gave up"),
    F("Retransmission","tcp.analysis.retransmission","Wireshark inferred a resend"),
    F("Zero window","tcp.analysis.zero_window","Receiver has no buffer left"),
    F("Window size","tcp.window_size_value","How much the receiver will accept")],
   [C("syn-no-synack","SYNs repeat with no reply",
      "Nothing is listening, or the SYN is filtered. A reset instead means something actively refused.",
      "Check the listener on the destination before suspecting the path"),
    C("retransmissions","tcp.analysis.retransmission appears repeatedly",
      "Packets are being lost. On a Labtris link this is often deliberate impairment rather than a fault.",
      "Check per-direction loss on the link, then look for a congested queue"),
    C("zero-window","tcp.analysis.zero_window is set",
      "The receiver stopped reading. This is an application problem wearing a network costume.",
      "Look at the receiving process, not the fabric")])

sk("udp", "UDP",
   "A stateless envelope. What matters is whether the port is right and whether anything comes back.",
   "udp",
   [FRAME, SRC, DST, F("Source port","udp.srcport","Sender's port"),
    F("Destination port","udp.dstport","Service being addressed"),
    F("Length","udp.length","Envelope size including header")],
   [C("no-response","datagrams sent with nothing returning",
      "Normal for one-way protocols; a fault for request/response ones. UDP will not tell you which.",
      "Check whether an ICMP port-unreachable came back — that is the real answer"),
    C("port-mismatch","destination port is not what the service uses",
      "The client is pointed somewhere else.",
      "Confirm the listener with ss -lnu on the destination")])

sk("ip", "IPv4 forwarding",
   "Whether packets are taking the path you think, and whether fragmentation is involved.",
   "ip",
   [FRAME, SRC, DST, F("TTL","ip.ttl","Decrements per hop — the hop count is the clue"),
    F("Protocol","ip.proto","6 TCP, 17 UDP, 1 ICMP, 89 OSPF"),
    F("More fragments","ip.flags.mf","Set on all but the last fragment"),
    F("Fragment offset","ip.frag_offset","Non-zero means this is not the first fragment")],
   [C("ttl-suggests-extra-hops","TTL is far below the expected start value",
      "More hops than the topology has, which usually means a loop or an unexpected path.",
      "Traceroute the same destination and compare against the diagram"),
    C("fragmentation","ip.flags.mf set or frag_offset non-zero",
      "Something is exceeding the path MTU. Fragments are fragile and often dropped by filters.",
      "Find the smallest MTU on the path; a tunnel is the usual culprit"),
    C("asymmetric-paths","forward and return traffic show different TTLs",
      "The two directions take different routes, which breaks stateful devices.",
      "Acceptable in a routed core, fatal through a firewall")])

sk("ipv6", "IPv6 forwarding",
   "The v6 equivalent, plus the neighbour discovery that replaces ARP.",
   "ipv6",
   [FRAME, F("Source","ipv6.src","Sending address"), F("Destination","ipv6.dst","Receiving address"),
    F("Hop limit","ipv6.hlim","The v6 TTL"),
    F("Next header","ipv6.nxt","6 TCP, 17 UDP, 58 ICMPv6")],
   [C("link-local-only","addresses are all fe80::",
      "No global addressing has been configured or advertised.",
      "Check for router advertisements before configuring addresses by hand"),
    C("no-neighbour-discovery","no ICMPv6 type 135/136 on a segment",
      "Nothing is resolving addresses, so nothing will forward.",
      "ICMPv6 must not be filtered — unlike ARP it is part of forwarding, not adjacent to it")])

sk("icmpv6", "ICMPv6 and neighbour discovery",
   "In IPv6 this carries address resolution, router discovery and error reporting. Filtering it breaks the network rather than hardening it.",
   "icmpv6",
   [FRAME, F("Source","ipv6.src","Sender"), F("Destination","ipv6.dst","Target"),
    F("Type","icmpv6.type","1 unreachable, 128/129 echo, 133 RS, 134 RA, 135 NS, 136 NA"),
    F("Code","icmpv6.code","Qualifies the type")],
   [C("rs-without-ra","type 133 repeating with no type 134",
      "No router is advertising on the segment, so hosts will not autoconfigure.",
      "Enable router advertisements on the gateway"),
    C("ns-without-na","type 135 with no type 136",
      "The target is not answering address resolution — the v6 equivalent of silent ARP.",
      "Confirm the target is up and not filtering ICMPv6")])

sk("http", "HTTP",
   "What was requested, what came back, and how long it took.",
   "http",
   [FRAME, SRC, DST, F("Method","http.request.method","GET, POST and friends"),
    F("URI","http.request.uri","What was asked for"),
    F("Host","http.host","Which virtual host"),
    F("Status","http.response.code","2xx fine, 4xx client, 5xx server"),
    F("Time","http.time","Seconds between request and response")],
   [C("no-response","a request with no matching response",
      "The server never answered. Look at TCP first — an unanswered request often has an unestablished connection underneath.",
      "Filter the same tcp.stream and check it completed a handshake"),
    C("slow-response","http.time is large",
      "The server is slow, or the path is. These look identical from one end.",
      "Compare http.time against the TCP round-trip on the same stream"),
    C("5xx","status is 5xx",
      "The server reached its own failure. Not a network problem.",
      "Read the server's logs; the capture has told you all it can")])

sk("tls", "TLS handshake",
   "Whether an encrypted session establishes, and if not, which side objected. The handshake is in the clear even when the data is not.",
   "tls",
   [FRAME, SRC, DST, F("Handshake type","tls.handshake.type","1 client hello, 2 server hello, 11 certificate"),
    F("Version","tls.record.version","Negotiated record version"),
    F("Server name","tls.handshake.extensions_server_name","SNI — which host the client asked for"),
    F("Alert","tls.alert_message.desc","Why a side gave up")],
   [C("hello-then-alert","a client hello answered with an alert",
      "The two cannot agree, or the certificate was rejected. The alert description names which.",
      "Read tls.alert_message.desc before changing anything"),
    C("sni-mismatch","server name is not the host you expect",
      "The client is asking for a different virtual host than intended.",
      "Check the client's configured URL against SNI"),
    C("no-server-hello","client hello with no reply",
      "TCP connected and TLS did not. Often a port serving plain HTTP.",
      "Confirm what the port actually speaks")])

sk("eigrp", "EIGRP",
   "Why an EIGRP adjacency does not form or routes do not appear. Cisco-proprietary, so this needs a vendor image.",
   "eigrp",
   [FRAME, SRC, F("Opcode","eigrp.opcode","1 update, 3 query, 4 reply, 5 hello"),
    F("AS number","eigrp.as","Must match between neighbours"),
    F("Sequence","eigrp.seq","Reliable transport sequence"),
    F("Flags","eigrp.flags","Init and restart bits")],
   [C("as-mismatch","eigrp.as differs between senders",
      "Neighbours in different autonomous systems never adjacate.",
      "Make the AS numbers match"),
    C("hellos-no-updates","opcode 5 only, never 1",
      "Adjacency is forming but no routes are exchanged — often an authentication or a K-value mismatch.",
      "Check the metric weights and any authentication on both ends"),
    C("stuck-in-active","queries repeat without replies",
      "A route is stuck active because a neighbour is not answering, which will eventually tear the adjacency down.",
      "Find the unresponsive neighbour; the query names the route")])

sk("isis", "IS-IS",
   "Adjacency and LSP exchange in IS-IS, the IGP most datacentre underlays use when they are not using BGP.",
   "isis",
   [FRAME, ESRC, F("PDU type","isis.type","Hello, LSP, CSNP or PSNP"),
    F("Circuit type","isis.hello.circuit_type","Level 1, level 2 or both"),
    F("LSP ID","isis.lsp.lsp_id","Identifies a link-state PDU and its originator")],
   [C("level-mismatch","circuit types do not overlap",
      "A level-1-only and a level-2-only interface will not adjacate.",
      "Set both ends to a compatible level"),
    C("hellos-no-lsps","hellos flow, no LSPs",
      "The adjacency is up but the database is not exchanging — often an MTU problem, since LSPs are larger than hellos.",
      "IS-IS is unusually sensitive to MTU; test with large pings before blaming config")])

sk("vrrp", "VRRP",
   "Which router owns the virtual address, and whether ownership is stable.",
   "vrrp",
   [FRAME, SRC, F("Type","vrrp.type","1 advertisement"),
    F("Virtual router ID","vrrp.virt_rtr_id","Identifies the group"),
    F("Priority","vrrp.prio","Highest wins; 255 is the address owner")],
   [C("two-masters","advertisements from two sources for one VRID",
      "A split brain. Both believe they are master, so the virtual MAC appears in two places.",
      "Check reachability between the pair — they cannot see each other"),
    C("priority-flapping","priority changes repeatedly",
      "Tracking is flapping an interface, and taking the gateway with it.",
      "Find the tracked object; the instability is there, not in VRRP")])

sk("hsrp", "HSRP",
   "The Cisco equivalent of VRRP. Same questions: who is active, and is that stable.",
   "hsrp",
   [FRAME, SRC, F("Opcode","hsrp.opcode","0 hello, 1 coup, 2 resign"),
    F("State","hsrp.state","Active, standby, speak, listen"),
    F("Priority","hsrp.priority","Highest wins"),
    F("Virtual IP","hsrp.virt_ip","The address being shared")],
   [C("two-active","two speakers in the active state",
      "Split brain — the pair cannot hear each other.",
      "HSRP hellos are multicast; check the segment carries them"),
    C("coup","opcode 1 appears",
      "A higher-priority router is taking over, which is preemption working as configured.",
      "Only a problem if it is repeating")])

sk("glbp", "GLBP",
   "Cisco first-hop redundancy that load-balances as well as failing over.",
   "glbp",
   [FRAME, SRC, F("Type","glbp.type","Hello and request/response types"),
    F("Priority","glbp.hello.priority","Election priority")],
   [C("no-load-sharing","all traffic uses one forwarder",
      "The group is working as failover rather than load balancing, often because only one forwarder is up.",
      "Check that the other members reached forwarder state")])

sk("pim", "PIM multicast routing",
   "Whether multicast routers are building the tree they should.",
   "pim",
   [FRAME, SRC, DST, F("Type","pim.type","0 hello, 1 register, 3 join/prune, 4 bootstrap")],
   [C("hellos-no-joins","type 0 only",
      "Neighbours exist but nothing is requesting traffic, so no tree is built.",
      "Check that a receiver has actually joined a group with IGMP"),
    C("registers-repeating","type 1 repeating",
      "The source is registering to the RP and not being switched to a shortest-path tree.",
      "Check the RP is reachable and correct on every router")])

sk("igmp", "IGMP group membership",
   "Whether a host has asked for a multicast group, and whether the switch heard.",
   "igmp",
   [FRAME, SRC, F("Type","igmp.type","0x11 query, 0x16 v2 report, 0x17 leave, 0x22 v3 report"),
    F("Group","igmp.maddr","The group being joined or left")],
   [C("reports-no-queries","reports with no querier",
      "No querier on the segment, so snooping will age out memberships and traffic will stop.",
      "Elect a querier — on a lab segment, often nothing is configured to be one"),
    C("version-mismatch","v2 and v3 messages mixed",
      "Hosts and routers disagree on version, so some memberships are invisible to the router.",
      "Pin the version on both ends")])


sk("cdp", "CDP neighbour discovery",
   "Cisco's equivalent of LLDP. Tells you what is plugged in where, on kit that speaks it.",
   "cdp",
   [FRAME, ESRC, F("Device ID","cdp.deviceid","Neighbour hostname"),
    F("Platform","cdp.platform","Hardware model"),
    F("Port ID","cdp.portid","Which of its ports"),
    F("Native VLAN","cdp.native_vlan","Native VLAN the neighbour believes in")],
   [C("native-vlan-mismatch","cdp.native_vlan differs across a trunk",
      "Two VLANs are being merged silently. CDP notices this when nothing else does.",
      "Fix the native VLAN on one end"),
    C("no-cdp","nothing on a link between two Cisco devices",
      "CDP is disabled, or a bridge in between is eating the multicast.",
      "Try LLDP as well; many devices run both")])

sk("dtp", "DTP trunk negotiation",
   "Whether two Cisco ports agreed to form a trunk, and whether you meant them to.",
   "dtp",
   [FRAME, ESRC, F("Version","dtp.version","Protocol version"),
    F("Domain","dtp.domain","VTP domain — must match to negotiate"),
    F("TLV type","dtp.tlv_type","Which attribute follows"),
    F("Operating status","dtp.tos","What the port is doing now"),
    F("Admin status","dtp.tas","What it was configured to do")],
   [C("unintended-trunk","a trunk formed on a port meant for a host",
      "Dynamic auto or desirable negotiated a trunk with whatever was plugged in. A security problem as much as a config one.",
      "Set access mode explicitly and turn negotiation off"),
    C("domain-mismatch","dtp.domain differs between ends",
      "Negotiation will not complete.",
      "Match the VTP domain or configure both ends statically")])

sk("vtp", "VTP",
   "VLAN database propagation between Cisco switches. Powerful and dangerous in equal measure.",
   "vtp",
   [FRAME, ESRC, F("Code","vtp.code","1 summary, 2 subset, 3 request advert"),
    F("VLAN name","vtp.vlan_info.vlan_name","VLANs being advertised")],
   [C("unexpected-advert","a switch advertising VLANs it should not own",
      "A switch with a higher revision number can overwrite the whole domain's VLAN database.",
      "Set switches you do not trust to transparent mode"),
    C("vlans-disappearing","subset adverts removing VLANs",
      "Exactly the failure VTP is famous for, usually after inserting a switch with stale configuration.",
      "Reset the revision number before attaching any switch to a VTP domain")])

sk("udld", "UDLD",
   "Detects a link that carries traffic one way only — the failure a physical check will not find.",
   "udld",
   [FRAME, ESRC, F("Version","udld.version","Protocol version"),
    F("Opcode","udld.opcode","Probe or echo"),
    F("Flags","udld.flags","Includes the recovery-related bits")],
   [C("probes-no-echoes","probes sent, nothing echoed",
      "The far end is not hearing us, or we are not hearing it. This is precisely what UDLD exists to catch.",
      "In aggressive mode the port will be err-disabled; that is the protocol working, not a fault")])

sk("pagp", "PAgP",
   "Cisco's pre-LACP bundling protocol. Same questions as LACP.",
   "pagp",
   [FRAME, ESRC, F("Flags","pagp.flags","Bundle state bits")],
   [C("no-bundle","frames exchanged but no bundle forms",
      "One end is likely in a mode that will not initiate.",
      "Prefer LACP for anything new; PAgP only exists where the kit demands it")])

sk("mpls", "MPLS label switching",
   "Which label a packet carries and where in the stack it sits.",
   "mpls",
   [FRAME, F("Label","mpls.label","The forwarding label"),
    F("Experimental","mpls.exp","Traffic class bits, used for QoS"),
    F("Bottom of stack","mpls.bottom","1 means this is the last label")],
   [C("unexpected-label-depth","more labels than the design uses",
      "An extra layer of encapsulation, or a service label where only a transport one was expected.",
      "Compare against the intended stack; MTU problems usually start here"),
    C("exp-not-set","mpls.exp is zero on traffic that should be prioritised",
      "QoS marking was not copied into the label stack, so the core will not honour it.",
      "Set the EXP bits at the edge")])

sk("ldp", "LDP",
   "Label distribution between MPLS routers. No LDP session means no labels means no LSP.",
   "ldp",
   [FRAME, SRC, DST, F("Message type","ldp.msg.type","Hello, initialisation, label mapping and friends")],
   [C("hellos-no-session","discovery hellos with no TCP session",
      "Discovery works and the session does not — usually a transport address that is not reachable.",
      "Check the router-id address is routable between the pair")])

sk("gre", "GRE tunnels",
   "What is inside a tunnel, and whether the tunnel itself is up.",
   "gre",
   [FRAME, SRC, DST, F("Protocol","gre.proto","What is encapsulated"),
    F("Key","gre.key","Distinguishes tunnels between the same endpoints")],
   [C("tunnel-up-no-traffic","GRE between endpoints but nothing inside",
      "The tunnel exists and nothing routes over it.",
      "Check the routing that should point into the tunnel interface"),
    C("fragmentation-inside","fragments appearing after encapsulation",
      "The tunnel overhead pushed packets past the path MTU.",
      "Lower the tunnel MTU or clamp MSS")])

sk("l2tp", "L2TP",
   "Layer 2 tunnelling, usually under a VPN.",
   "l2tp",
   [FRAME, SRC, DST, F("Type","l2tp.type","Control or data message"),
    F("Flags","l2tp.flags","Length, sequence and offset bits")],
   [C("control-no-data","control messages only",
      "The tunnel negotiated and no session carries traffic.",
      "Check the session layer above the tunnel")])

sk("isakmp", "IKE / ISAKMP",
   "VPN negotiation. If phase 1 does not complete, nothing above it will.",
   "isakmp",
   [FRAME, SRC, DST, F("Exchange type","isakmp.exchangetype","Identity protection, aggressive, informational"),
    F("Message ID","isakmp.messageid","Zero in phase 1, non-zero in phase 2")],
   [C("phase1-never-completes","exchanges repeat with no phase 2",
      "Proposal mismatch or an authentication failure. Both look the same from outside.",
      "Compare the proposals on each side — encryption, hash, DH group, lifetime"),
    C("informational-then-silence","an informational exchange followed by nothing",
      "One side sent a delete or an error and gave up.",
      "The far end's logs will name the reason; the capture will not")])

sk("esp", "ESP",
   "Encrypted VPN payload. You can see that it flows and little else, which is itself useful.",
   "esp",
   [FRAME, SRC, DST, F("SPI","esp.spi","Identifies the security association"),
    F("Sequence","esp.sequence","Replay protection counter")],
   [C("one-way-esp","ESP in one direction only",
      "One side is encrypting and the other is not decrypting, or the return SA is missing.",
      "Compare the SPIs each end expects"),
    C("sequence-gaps","esp.sequence jumps",
      "Packets are being lost inside the tunnel.",
      "Look at the underlay path, not the VPN config")])

sk("ah", "AH",
   "IPsec authentication without encryption. Rare, and broken by any NAT on the path.",
   "ah",
   [FRAME, SRC, DST, F("SPI","ah.spi","Security association"),
    F("Sequence","ah.sequence","Replay counter"),
    F("Next header","ah.next_header","What follows")],
   [C("ah-through-nat","AH traffic crossing a NAT",
      "AH authenticates the IP header, so NAT invalidates it by definition. This cannot be made to work.",
      "Use ESP instead")])

sk("radius", "RADIUS",
   "Authentication, authorisation and accounting exchanges.",
   "radius",
   [FRAME, SRC, DST, F("Code","radius.code","1 access-request, 2 accept, 3 reject, 11 challenge"),
    F("Identifier","radius.id","Matches a request to its response")],
   [C("request-no-response","access-requests repeating",
      "The server is unreachable or the shared secret is wrong — a wrong secret often produces silence, not a reject.",
      "Check reachability first, then the secret"),
    C("reject","code 3",
      "The server answered and said no. That is an authorisation answer, not a network fault.",
      "The server's logs have the reason")])

sk("tacacs", "TACACS+",
   "Cisco's AAA protocol. Unlike RADIUS it encrypts the whole body.",
   "tacacs",
   [FRAME, SRC, DST, F("Type","tacplus.type","Authentication, authorization or accounting")],
   [C("no-response","requests with no reply",
      "Server unreachable, or the key is wrong and it is dropping silently.",
      "TACACS+ uses TCP 49 — confirm the handshake completes before suspecting the key")])

sk("snmp", "SNMP",
   "Polling and traps. Most SNMP problems are credentials or ACLs rather than the protocol.",
   "snmp",
   [FRAME, SRC, DST, F("Version","snmp.version","0 v1, 1 v2c, 3 v3"),
    F("Community","snmp.community","Plain text in v1 and v2c"),
    F("Data","snmp.data","The PDU type — get, getnext, response, trap")],
   [C("get-no-response","gets with no responses",
      "Wrong community, an ACL on the agent, or the agent is not running.",
      "v1 and v2c send the community in clear — read it from the capture and compare"),
    C("v2c-in-production","version is 0 or 1 outside a lab",
      "Credentials are on the wire in plain text.",
      "Fine in a lab, and worth noticing that you can read them")])

sk("ssh", "SSH",
   "Version exchange and whether the session gets past it. The interesting part is encrypted.",
   "ssh",
   [FRAME, SRC, DST, F("Protocol","ssh.protocol","The banner each side sends"),
    F("Message code","ssh.message_code","Key exchange and authentication stages")],
   [C("banner-then-close","banners exchanged, connection closes",
      "No common key exchange or cipher — often an old client against a hardened server.",
      "The banners name both versions; compare them")])

sk("telnet", "Telnet",
   "Unencrypted remote access. Useful in a lab precisely because you can read it.",
   "telnet",
   [FRAME, SRC, DST, F("Data","telnet.data","The session contents, in clear")],
   [C("credentials-visible","a login prompt and its response in the capture",
      "Everything including the password is readable. That is the lesson, not a fault.",
      "Use it to demonstrate why SSH exists")])

sk("eapol", "802.1X / EAPOL",
   "Port-based authentication. The supplicant, authenticator and server each fail differently.",
   "eapol",
   [FRAME, ESRC, F("Version","eapol.version","EAPOL version"),
    F("Type","eapol.type","Start, logoff, key, or EAP packet"),
    F("EAP code","eap.code","1 request, 2 response, 3 success, 4 failure"),
    F("EAP type","eap.type","Which method — MD5, TLS, PEAP")],
   [C("start-no-request","EAPOL-Start with no EAP request",
      "The authenticator is not configured for 802.1X on this port, or is not forwarding to the server.",
      "Check the port before the supplicant"),
    C("eap-failure","eap.code is 4",
      "The server rejected the credentials or the method.",
      "The RADIUS exchange behind it has the reason"),
    C("no-eapol-on-a-labtris-link","nothing matches on a link that should authenticate",
      "EAPOL uses a reserved multicast address that a Linux bridge swallows by default. Labtris forwards this range deliberately.",
      "On another emulator, check the bridge group_fwd_mask")])

sk("nbns", "NetBIOS name service",
   "Legacy Windows name resolution. Mostly seen as background noise that explains broadcast volume.",
   "nbns",
   [FRAME, SRC, F("Name","nbns.name","The NetBIOS name queried")],
   [C("broadcast-volume","frequent broadcasts from many hosts",
      "Normal for a Windows segment and a common surprise in a quiet lab.",
      "Not a fault; useful for explaining why broadcast domains are sized as they are")],
   legacy=True)

sk("nhrp", "NHRP",
   "Next-hop resolution in DMVPN. Usually the reason a spoke-to-spoke tunnel does or does not form.",
   "nhrp",
   [FRAME, SRC, DST, F("Packet size","nhrp.hdr.pktsz","Header length field")],
   [C("registration-no-reply","spokes registering with no response",
      "The hub is not answering, so no spoke will learn any other spoke.",
      "Check the hub's NHRP configuration and reachability")])

sk("msdp", "MSDP",
   "Multicast source discovery between rendezvous points in different domains.",
   "msdp",
   [FRAME, SRC, DST, F("Type","msdp.type","Source-active and keepalive messages")],
   [C("no-source-active","peering up but no SA messages",
      "No sources are being advertised, so cross-domain multicast will not work.",
      "Confirm a source is actually sending in the origin domain")])

sk("dvmrp", "DVMRP",
   "An early multicast routing protocol. Rare outside teaching material.",
   "dvmrp",
   [FRAME, SRC, F("Type","dvmrp.type","Probe, report, prune, graft")],
   [C("probes-only","probes with no reports",
      "Neighbours are found but no routes exchanged.",
      "Largely of historical interest; PIM replaced this")],
   legacy=True)

sk("auto_rp", "Auto-RP",
   "Cisco's way of announcing multicast rendezvous points before bootstrap router existed.",
   "auto_rp",
   [FRAME, SRC, F("Version","auto_rp.version","Protocol version"),
    F("Type","auto_rp.type","Announce or discovery"),
    F("RP count","auto_rp.rp_count","How many RPs are named"),
    F("Group","auto_rp.group_num","Groups this RP serves")],
   [C("announcements-no-discovery","announce messages with no discovery",
      "The mapping agent is not relaying, so routers never learn the RP.",
      "Check the mapping agent before the RP itself")])

sk("rip", "RIP",
   "Distance-vector routing. Simple enough that the capture tells you almost everything.",
   "rip",
   [FRAME, SRC, DST, F("Command","rip.command","1 request, 2 response"),
    F("Network","rip.ip","Advertised prefix"),
    F("Metric","rip.metric","Hop count; 16 means unreachable")],
   [C("metric-16","routes advertised with metric 16",
      "Poison reverse — the route is being withdrawn, not offered.",
      "Expected during convergence; a problem if it persists"),
    C("no-updates","nothing every 30 seconds",
      "RIP is not running on the interface, or updates are being filtered.",
      "RIP v2 uses multicast 224.0.0.9; v1 broadcasts. A version mismatch looks like silence")])

sk("llc", "LLC",
   "The 802.2 header under non-IP legacy traffic, notably STP.",
   "llc",
   [FRAME, ESRC, F("DSAP","llc.dsap","Destination service access point"),
    F("SSAP","llc.ssap","Source service access point")],
   [C("unexpected-sap","a SAP value you do not recognise",
      "Legacy protocol traffic on a modern segment.",
      "Identify it before assuming it is harmless")],
   legacy=True)

sk("ethernet", "Ethernet framing",
   "The bottom of the stack. Useful when nothing above it makes sense.",
   "eth",
   [FRAME, ESRC, F("Destination MAC","eth.dst","Unicast, multicast or broadcast"),
    F("EtherType","eth.type","0x0800 IPv4, 0x0806 ARP, 0x86dd IPv6, 0x8100 VLAN, 0x8808 MAC control")],
   [C("unexpected-broadcast-volume","a large share of frames to ff:ff:ff:ff:ff:ff",
      "A broadcast storm, or simply a large broadcast domain.",
      "Check for a loop before assuming it is scale"),
    C("unknown-ethertype","an EtherType you do not recognise",
      "Something is speaking a protocol the design did not account for.",
      "0x8808 is MAC control — see the pfc skill")])

sk("frame_relay", "Frame Relay",
   "Legacy WAN encapsulation. Present for completeness and for old study material.",
   "fr",
   [FRAME, F("DLCI","fr.dlci","Identifies the virtual circuit"),
    F("Control","fr.control","Frame type")],
   [C("dlci-mismatch","a DLCI the far end does not expect",
      "Circuit identifiers are locally significant and must be mapped correctly at each end.",
      "Compare the mapping on both routers")],
   legacy=True)

sk("hdlc", "Cisco HDLC",
   "The default serial encapsulation on Cisco kit. Legacy, and still on exams.",
   "hdlc",
   [FRAME, F("Protocol","ppp.protocol","What is carried — HDLC reuses the PPP protocol numbers")],
   [C("keepalive-mismatch","one end keepalive, other end not",
      "The link will flap. Cisco HDLC keepalives must agree.",
      "Match keepalive settings on both ends")],
   legacy=True)

sk("ppp", "PPP",
   "Point-to-point links, including the LCP and NCP negotiation that decides whether anything runs.",
   "ppp",
   [FRAME, F("Protocol","ppp.protocol","0xc021 LCP, 0x8021 IPCP, 0xc023 PAP, 0xc223 CHAP")],
   [C("lcp-loops","LCP negotiating repeatedly",
      "The two ends cannot agree on options, or authentication keeps failing after LCP succeeds.",
      "Watch for CHAP or PAP immediately before each restart"),
    C("lcp-up-no-ipcp","LCP completes and IPCP does not",
      "The link is up at layer 2 and no addressing is agreed.",
      "Check the address pool or the static addresses on both ends")])

sk("slarp", "SLARP",
   "Cisco serial line address resolution and keepalives. Legacy.",
   "slarp",
   [FRAME, F("Packet type","slarp.ptype","Address request, reply, or keepalive"),
    F("Address","slarp.address","Address being resolved"),
    F("Sequence","slarp.mysequence","Keepalive counter")],
   [C("sequence-not-advancing","mysequence stops incrementing",
      "The far end has stopped answering keepalives; the line will drop.",
      "Treat as a layer 1 problem until proven otherwise")],
   legacy=True)

sk("isl", "ISL",
   "Cisco's pre-802.1Q VLAN tagging. Obsolete.",
   "isl",
   [FRAME, F("Destination","isl.dst","ISL header destination")],
   [C("isl-present","any ISL frames at all",
      "Something very old is trunking. 802.1Q replaced this.",
      "Migrate to dot1q")],
   legacy=True)

sk("loop", "Ethernet loopback",
   "The 0x9000 loopback protocol, occasionally used for link testing.",
   "loop",
   [FRAME, ESRC, F("Function","loop.function","Reply or forward"),
    F("Skip count","loop.skipcount","Position in the forwarding list")],
   [C("unexpected-loopback","loopback frames nobody initiated",
      "A device is testing a link, or a loop is reflecting frames.",
      "Check for a physical loop")],
   legacy=True)

sk("dec_dna", "DECnet",
   "Historic protocol suite. Present for completeness.",
   "dec_dna",
   [FRAME, F("Flags","dec_dna.flags","Routing flags")],
   [C("decnet-present","any DECnet traffic",
      "Almost certainly not intentional on a modern network.",
      "Identify the source")],
   legacy=True)

sk("ocsp", "OCSP",
   "Certificate revocation checking. A slow or blocked OCSP responder stalls TLS handshakes.",
   "ocsp",
   [FRAME, SRC, DST, F("Response type","ocsp.responseType.id","Which response format")],
   [C("no-response","requests with no reply",
      "The responder is unreachable and clients may hang rather than fail fast.",
      "Check whether the client is configured to soft-fail")])

sk("wccp", "WCCP",
   "Redirecting traffic to a cache or appliance.",
   "wccp",
   [FRAME, SRC, DST, F("Message","wccp.message","Here-I-am, I-see-you, redirect assign"),
    F("Version","wccp.version","Protocol version")],
   [C("here-i-am-no-i-see-you","the appliance announces and the router never answers",
      "The service group is not configured on the router, or the numbers do not match.",
      "Compare the service group ID on both sides")])

def yaml_escape(s):
    return s.replace('"', "'")

def emit(outdir):
    out = pathlib.Path(outdir); out.mkdir(parents=True, exist_ok=True)
    for key, d in P.items():
        lines = [f'name: {d["name"]}', "description: >"]
        for chunk in wrap(d["description"], 72):
            lines.append("  " + chunk)
        lines.append(f'protocol_key: {key}')
        if d.get("legacy"):
            lines.append("legacy: true  # kept for study material, not for deployment")
        lines += [f'display_filter: {d["display_filter"]}', "fields:"]
        for label, field, desc in d["fields"]:
            lines += [f'  - label: "{label}"', f'    tshark_field: {field}',
                      f'    description: "{yaml_escape(desc)}"']
        lines.append("checks:")
        for c in d["checks"]:
            lines.append(f'  - name: {c["name"]}')
            lines.append(f'    when: "{yaml_escape(c["when"])}"')
            lines.append("    means: >")
            for chunk in wrap(c["means"], 68):
                lines.append("      " + chunk)
            lines.append(f'    next: "{yaml_escape(c["next"])}"')
        (out / f"{key}.yaml").write_text("\n".join(lines) + "\n")
    return len(P)

def wrap(text, width):
    words, line, out = " ".join(text.split()).split(), "", []
    for w in words:
        if len(line) + len(w) + 1 > width:
            out.append(line); line = w
        else:
            line = f"{line} {w}".strip()
    if line: out.append(line)
    return out

if __name__ == "__main__":
    n = emit(sys.argv[1])
    print(f"emitted {n} skills")
