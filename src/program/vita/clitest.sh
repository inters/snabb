#!/bin/bash

set -e
set -x

name=vita-clitest-test-$$
conf=$(mktemp)

./vita --name $name &
vita=$!

function cleanup { kill $vita; }
trap cleanup EXIT HUP INT QUIT TERM

sleep 1

program/vita/genconf.snabb < program/vita/clitest.conf > $conf

./snabb config set $name / < $conf

[ $(./snabb config get $name /public-interface4[ip=172.16.0.10]/nexthop-ip) \
      = 172.17.0.10 ]

[ $(./snabb config get $name /route4[id=test1]/spi) = 1001 ]

./snabb config set $name /mtu 1500

[ $(./snabb config get $name /mtu) = 1500 ]

sleep 2

[ $(./snabb config get-state $name \
            /gateway-state/private-router/route-errors) = 0 ]

./snabb config set $name / <<EOF
EOF

sleep 2
