#!/usr/bin/env bash

set -e
set -x

tid=$$

pr0=pr0-$tid
vpr0=v$pr0

pr1=pr1-$tid
vpr1=v$pr1

vpu0=vpu0-$tid
vpu1=vpu1-$tid

vita0name=vita0-vethtest-$tid
./vita --xdp --name $vita0name &
vita0=$!

vita1name=vita1-vethtest-$tid
./vita --xdp --name $vita1name &
vita1=$!

(sleep 60
 echo "Test timeout!"
 kill -SIGTERM $$
 # Need to really kill it for Travis!?
 sleep 1
 kill -SIGKILL $$) &
timeout=$!

iperfs0="" # To be assigned
iperfs1="" # ...

function cleanup {
    kill $timeout || true
    [ -z $iperfs0 ] || kill $iperfs0 || true
    [ -z $iperfs1 ] || kill $iperfs1 || true
    kill $vita0 || true
    kill $vita1 || true
    ip link delete $vpu0 || true
    ip link delete $vpr0 || true
    ip link delete $vpr1 || true
    ip netns delete $pr0 || true
    ip netns delete $pr1 || true
}
trap cleanup EXIT HUP INT QUIT TERM

# Test setup

ip link add $vpu0 type veth peer name $vpu1

ip link set $vpu0 address 02:00:00:00:00:01
ip address add dev $vpu0 local 10.20.0.1
ip link set $vpu0 up

ip link set $vpu1 address 02:00:00:00:01:01
ip address add dev $vpu1 local 10.20.0.2
ip link set $vpu1 up

ip netns add $pr0
ip netns add $pr1
ip netns exec $pr0 ip link set lo up
ip netns exec $pr1 ip link set lo up

ip link add $vpr0 type veth peer name $pr0
ip link set $pr0 netns $pr0

ip link set $vpr0 address 02:00:00:00:00:02
ip address add dev $vpr0 local 10.10.1.1
ip link set $vpr0 up

ip netns exec $pr0 ethtool --offload $pr0  rx off tx off
ip netns exec $pr0 ip address add dev $pr0 local 10.10.1.2/24
ip netns exec $pr0 ip link set $pr0 mtu 1440
ip netns exec $pr0 ip link set $pr0 up
ip netns exec $pr0 ip route add 10.10.2.0/24 via 10.10.1.1 src 10.10.1.2 dev $pr0
ip netns exec $pr0 ip route add default via 10.10.1.2 dev $pr0

ip link add $vpr1 type veth peer name $pr1
ip link set $pr1 netns $pr1

ip link set $vpr1 address 02:00:00:00:01:02
ip address add dev $vpr1 local 10.10.2.1
ip link set $vpr1 up

ip netns exec $pr1 ethtool --offload $pr1  rx off tx off
ip netns exec $pr1 ip address add dev $pr1 local 10.10.2.2/24
ip netns exec $pr1 ip link set $pr1 mtu 1440
ip netns exec $pr1 ip link set $pr1 up
ip netns exec $pr1 ip route add 10.10.1.0/24 via 10.10.2.1 src 10.10.2.2 dev $pr1
ip netns exec $pr1 ip route add default via 10.10.2.2 dev $pr1

# Start iperf servers
ip netns exec $pr0 iperf -s &
iperfs0=$!
ip netns exec $pr1 iperf -s &
iperfs1=$!

# Wait until vitas are ready.
until ./snabb config get $vita0name /; do sleep .1; done
until ./snabb config get $vita1name /; do sleep .1; done

# Configure vitas
./snabb config set $vita0name / <<EOF
public-interface4 {
  ifname $vpu0;
  ip 10.20.0.1;
  mac 02:00:00:00:00:01;
  nexthop-ip 10.20.0.2;
}
private-interface4 {
  ifname $vpr0;
  ip 10.10.1.1;
  mac 02:00:00:00:00:02;
  nexthop-ip 10.10.1.2;
}
route4 {
  id test1;
  gateway { ip 10.20.0.2; }
  net "10.10.2.0/24";
  preshared-key 0000000000000000000000000000000000000000000000000000000000000001;
  spi 1001;
}
EOF
./snabb config set $vita1name / <<EOF
public-interface4 {
  ifname $vpu1;
  ip 10.20.0.2;
  mac 02:00:00:00:01:01;
  nexthop-ip 10.20.0.1;
}
private-interface4 {
  ifname $vpr1;
  ip 10.10.2.1;
  mac 02:00:00:00:01:02;
  nexthop-ip 10.10.2.2;
}
route4 {
  id test1;
  gateway { ip 10.20.0.1; }
  net "10.10.1.0/24";
  preshared-key 0000000000000000000000000000000000000000000000000000000000000001;
  spi 1001;
}
EOF

# Wait until SA is negotiated
until ip netns exec $pr0 ping -c 1 10.10.2.2; do sleep 1; done

# Test pings
ip netns exec $pr0 ping -c 1 10.10.1.1
ip netns exec $pr0 ping -c 1 10.10.2.1
ip netns exec $pr0 ping -c 1 10.10.2.2
ip netns exec $pr1 ping -c 1 10.10.2.1
ip netns exec $pr1 ping -c 1 10.10.1.1
ip netns exec $pr1 ping -c 1 10.10.1.2

# Test iperf
ip netns exec $pr0 iperf -c 10.10.2.2
ip netns exec $pr0 iperf -c 10.10.2.2 -u
ip netns exec $pr1 iperf -c 10.10.1.2
ip netns exec $pr1 iperf -c 10.10.1.2 -u

# Test traceroute
[ $(ip netns exec $pr0 traceroute -m 3 -n 10.10.2.2 | tee /dev/stderr \
        | egrep '[0-9]+\s+[0-9]+.[0-9]+.[0-9]+.[0-9]+' | wc -l) \
      = 3 ]
[ $(ip netns exec $pr0 traceroute -m 3 -n -I 10.10.2.2 | tee /dev/stderr \
        | egrep '[0-9]+\s+[0-9]+.[0-9]+.[0-9]+.[0-9]+' | wc -l) \
      = 3 ]
[ $(ip netns exec $pr1 traceroute -m 3 -n 10.10.1.2 | tee /dev/stderr \
        | egrep '[0-9]+\s+[0-9]+.[0-9]+.[0-9]+.[0-9]+' | wc -l) \
      = 3 ]
[ $(ip netns exec $pr1 traceroute -m 3 -n -I 10.10.1.2 | tee /dev/stderr \
        | egrep '[0-9]+\s+[0-9]+.[0-9]+.[0-9]+.[0-9]+' | wc -l) \
      = 3 ]
