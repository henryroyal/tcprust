#!/usr/bin/env bash

~/.cargo/bin/cargo b --release &&
  # see: http://man7.org/linux/man-pages/man7/capabilities.7.html
  sudo setcap cap_net_admin=eip ./target/release/tcprust || exit 1

./target/release/tcprust &

pid=$!
ext=$?
echo $ext
if [[ $ext -ne 0 ]]; then
  echo "FAIL: ${ext}"
  exit $ext
fi

sudo ip addr add 10.12.1.1/24 dev tun0
sudo ip link set up dev tun0
echo "tun0 on 10.12.1.1/24"
trap "kill ${pid}" INT TERM

wait $pid
