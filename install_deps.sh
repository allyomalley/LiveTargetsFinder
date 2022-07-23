#!/bin/sh

echo "Cloning massDNS."
git clone https://github.com/blechschmidt/massdns.git

echo "Cloning masscan."
git clone https://github.com/robertdavidgraham/masscan.git

cd massdns
git checkout 65331fb528755621650a0fbacff12102cfdcdde9
if [ "$(uname)" == "Darwin" ]; then
	make nolinux
else
	make
fi
cd ..

cd masscan
if [ "$(uname)" == "Darwin" ]; then
	make
else
	sudo apt-get install git gcc make libpcap-dev && make
fi
cd ..
