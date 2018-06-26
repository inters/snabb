# Testing Vita with `snabb loadtest`

Say you have some test hardware and want to evaluate how Vita runs on it. This issue will walk you through how I test Vita on a low-budget testing box using `snabb loadtest`. The test setup will look like this:

![vita-loadtest](vita-loadtest.png)

My low-budget testing box has an AMD Ryzen 5 1600 CPU (6 cores, 12 threads) and two 4‑port Intel i350 1 GbE NICs. Our test setup will use six out of the total eight 1 GbE ports and run two Vita nodes simultaneously, so having many hardware threads and Ethernet interfaces does not hurt. The interfaces are wired like this (you can get the PCI bus address of an interface via `lspci`):

    22:00.0 ←→ 23:00.0
    22:00.1 ←→ 23:00.1
    22:00.2 ←→ 23:00.2

> **Note:** Snabb needs Linux to be booted with `iommu=off` for its device drivers to function. Additionally, I have turned off AMD Turbo Core in BIOS to get dependable CPU frequency. Intel calls the equivalent feature Turbo Boost.

So lets get started by cloning Vita, building a test build, and switching to the `src/` directory:

    $ git clone https://github.com/inters/vita
    $ cd vita
    $ make -j # builds a test build by default
    $ cd src

We can start by running the the software-based benchmark test to get a baseline of what we can expect from this machine:

    $ sudo program/vita/test.snabb IMIX 10e6 1 1,2,3,4,5
                                   ^    ^    ^ ^
                                   |    |    | \- CPU hdw. threads to bind to
                                   |    |    \- # of routes to test with
                                   |    \- # of packets
                                   \- packet size

That will print a bunch of output and then something like:

    Processed 10.0 million packets in 4.77 seconds (3425807426 bytes; 5.74 Gbps)
    Made 180,398 breaths: 55.43 packets per breath; 26.45us per breath
    Rate(Mpps):	2.096

And once more for 60 byte packets:
    
    $ sudo program/vita/test.snabb 60 10e6 1 1,2,3,4,5
    ...
    Processed 10.0 million packets in 2.29 seconds (600004080 bytes; 2.10 Gbps)
    Made 135,754 breaths: 73.66 packets per breath; 16.87us per breath
    Rate(Mpps):	4.367

The results suggest that setup should be able to handle 1 GbE line-rate at any packet size without breaking a sweat. So let’s confirm that with an end-to-end test using [snabb loadtest find-limit](https://github.com/inters/vita/tree/master/src/program/loadtest/find-limit).

`loadtest` takes Pcap records, replays the contained packets in a loop on its interfaces, and checks if the number of packets received match the number of packets it sent. So we need to configure our Vita nodes to form such a loop and generate Pcap records to use as test traffic accordingly. This is the configuration `node1.conf` for the first Vita node with a single route (do not start copying it yet, you will not have to write these by hand for testing purposes):

    private-interface {
      pci 23:00.0;
      ip4 172.16.0.10;
      nexthop-ip4 172.16.0.1;
      nexthop-mac 02:00:00:00:00:00;
    }
    public-interface {
      pci 22:00.1;
      ip4 172.16.0.10;
      nexthop-ip4 172.17.0.10;
    }
    route {
      id test1;
      gw-ip4 172.17.0.10;
      net-cidr4 "172.17.1.0/24";
      preshared-key 0000000000000000000000000000000000000000000000000000000000000000;
      spi 1001;
    }

Most of it should be fairly self explanatory: we assign the desired ports via their PCI bus addresses, and set the interface’s own addresses as well as the addresses of the next hops. In this case, the private and public interface addresses are the same, but they need not be. The next hop of the private interface (this would normally be your local router) will be `snabb loadtest`. Since `loadtest` does not speak ARP, we configure a fixed MAC destination address for this next hop. This will prevent Vita from attempting to look up the next hop’s MAC addresses via ARP, and instead use the preconfigured address. The next hop of the public interface (this would normally be your gateway to the Internet) is configured to be the other Vita node in the test setup. Finally, we define a single route to the subnet `172.17.1.0/24` via the second Vita node with a dummy key. For the other Vita node, `node2.conf` is symmetric:

    private-interface {
      pci 22:00.2;
      ip4 172.17.0.10;
      nexthop-ip4 172.17.0.1;
      nexthop-mac 02:00:00:00:00:00;
    }
    public-interface {
      pci 23:00.1;
      ip4 172.17.0.10;
      nexthop-ip4 172.16.0.10;
    }
    route {
      id test1;
      gw-ip4 172.16.0.10;
      net-cidr4 "172.16.1.0/24";
      preshared-key 0000000000000000000000000000000000000000000000000000000000000000;
      spi 1001;
    }

Because typing out configuration files for testing gets old fast, and we still need matching Pcap records, Vita comes with a utility that generates both of these from a meta-configuration file. For the first node we have `gentest-node1.conf`:

    private-interface {
      pci 23:00.0;
      ip4 172.16.0.10;
      nexthop-ip4 172.16.0.1;
      nexthop-mac 02:00:00:00:00:00;
    }
    public-interface {
      pci 22:00.1;
      ip4 172.16.0.10;
      nexthop-ip4 172.17.0.10;
    }
    route-prefix "172.17";
    nroutes 1;
    packet-size 60;

…and for the second node `gentest-node2.conf`:

    private-interface {
      pci 22:00.2;
      ip4 172.17.0.10;
      nexthop-ip4 172.17.0.1;
      nexthop-mac 02:00:00:00:00:00;
    }
    public-interface {
      pci 23:00.1;
      ip4 172.17.0.10;
      nexthop-ip4 172.16.0.10;
    }
    route-prefix "172.16";
    nroutes 1;
    packet-size 60;

These meta-configurations allows us to define the number of routes to use in the test case, as well the packet size of the packets in the generated Pcap records. We can then generate equivalent configurations to the above, and more importantly Pcap records with adequate test traffic using `gentest.snabb`:

    $ sudo program/vita/gentest.snabb gentest-node1.conf node1.conf node1-private-in.pcap
    $ sudo program/vita/gentest.snabb gentest-node2.conf node2.conf node2-private-in.pcap

Enough prologue, now we have everything to start testing. To start the two vita nodes in the background (we bind both key manager processes to the same hardware thread as they are not CPU hungry under normal circumstances):

    $ sudo ./vita --cpu 1,2,3,4,5 node1.conf &> node1.log &
    $ sudo ./vita --cpu 1,6,7,8,9 node2.conf &> node2.log &

And now we can run `find-limit`, which will determine the No-Drop-Rate (NDR) by means of a binary search:

    $ sudo ./snabb loadtest find-limit -b 1e9 --cpu 10 \
        node1-private-in.pcap node1 node2 22:00.0 \
        node2-private-in.pcap node2 node1 23:00.2

The `-b` flag tells it that the maximum rate is 1 GbE as limited by the NIC, and the two “streams” are configured so that packets from `node1-private-in.pcap` will be sent via the private port of node #1 (wired to `22:00.0`) and matched against the egress traffic of node #2 (wired to 23:00.2), and vice versa. `find-limit` will print a bunch of output and finally announce the effective NDR it has determined, in my case (partially redacted):

    Applying 0.500000 Gbps of load.
      node1:
        TX 744128 packets (0.744128 MPPS), 44647680 bytes (0.500054 Gbps)
        RX 746467 packets (0.746467 MPPS), 44788020 bytes (0.501626 Gbps)
        Loss: 0 ingress drop + -2339 packets lost (-0.314328%)
      node2:
        TX 744128 packets (0.744128 MPPS), 44647680 bytes (0.500054 Gbps)
        RX 746439 packets (0.746439 MPPS), 44786340 bytes (0.501607 Gbps)
        Loss: 0 ingress drop + -2311 packets lost (-0.310565%)
    ...
    Applying 0.625000 Gbps of load.
      node1:
        TX 930058 packets (0.930058 MPPS), 55803480 bytes (0.624999 Gbps)
        RX 907731 packets (0.907731 MPPS), 54463860 bytes (0.609995 Gbps)
        Loss: 0 ingress drop + 22327 packets lost (2.400603%)
      node2:
        TX 930058 packets (0.930058 MPPS), 55803480 bytes (0.624999 Gbps)
        RX 907701 packets (0.907701 MPPS), 54462060 bytes (0.609975 Gbps)
        Loss: 0 ingress drop + 22357 packets lost (2.403829%)
    Failed.
    ...
    Applying 0.609000 Gbps of load.
      node1:
        TX 906253 packets (0.906253 MPPS), 54375180 bytes (0.609002 Gbps)
        RX 907728 packets (0.907728 MPPS), 54463680 bytes (0.609993 Gbps)
        Loss: 0 ingress drop + -1475 packets lost (-0.162758%)
      node2:
        TX 906253 packets (0.906253 MPPS), 54375180 bytes (0.609002 Gbps)
        RX 907623 packets (0.907623 MPPS), 54457380 bytes (0.609923 Gbps)
        Loss: 0 ingress drop + -1370 packets lost (-0.151172%)
    Success.
    0.609

Huh, 0.609 Gbps. How come? This figure is explained if you consider the IPsec ESP overhead added to the packets while in transit between Vita nodes. In tunnel mode, the overhead for 60 byte packets will be 54 bytes (encapsulating IP header + ESP protocol header overhead + zero bytes of padding to four byte boundary), so the effective packet size between the public interfaces is 114 bytes. If we add the 24 bytes of Ethernet overhead (7 bytes preamble + 1 byte start-of-frame + 4 bytes CRC + 12 bytes interframe gap) and calculate the ratio we get `(84 / 138) * 100 = ~60.869%`. This adds up.

You can test with different configurations (try `packet-size IMIX`, or `nroutes 40`) by editing `gentest-node?.conf` and rerunning the `gentest.snabb` commands from above.  The Vita nodes will pick up the new configurations while they are running. With increasing packet sizes the packet overhead in transit will be less visible.

There is also [snabb loadtest transient](https://github.com/inters/vita/tree/master/src/program/loadtest/transient) which can simulate basic traffic patterns like `ramp_up_down`:

    $ sudo ./snabb loadtest transient -b 1e9 --cpu 10 \
        node1-private-in.pcap node1 node2 22:00.0 \
        node2-private-in.pcap node2 node1 23:00.2
