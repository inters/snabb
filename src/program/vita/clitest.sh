#!/usr/bin/env bash

set -e
set -x

name=vita-clitest-test-$$

./vita --name $name &
vita=$!

(sleep 20; echo "Test timeout!"; kill -SIGTERM $$;) &
timeout=$!

function cleanup {
    kill $vita || true
    kill $timeout || true
}
trap cleanup EXIT HUP INT QUIT TERM

until ./snabb config get $name /; do sleep .1; done

program/vita/genconf.snabb < program/vita/clitest.conf \
    | ./snabb config set $name /

[ $(./snabb config get $name /public-interface4[ip=172.16.0.10]/nexthop-ip) \
      = 172.17.0.10 ]

[ $(./snabb config get $name /route4[id=test1]/spi) = 1001 ]

./snabb config set $name /mtu 1500

[ $(./snabb config get $name /mtu) = 1500 ]

until ./snabb config get-state $name /gateway-state/private-router \
              | grep route-errors
do sleep .1; done

[ $(./snabb config get-state $name \
            /gateway-state/private-router/route-errors) = 0 ] \
    || ./snabb config get-state $name /gateway-state

./snabb config set $name / <<EOF
EOF

[ $(./snabb config get $name /mtu) -gt 1500 ]
