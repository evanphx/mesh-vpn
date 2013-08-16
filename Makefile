mesh-vpn: *.go
	go build -o mesh-vpn *.go

deb: mesh-vpn
	mkdir -p usr/sbin
	cp mesh-vpn usr/sbin
	fpm -s dir -t deb -n "mesh-vpn" -v 1.0 usr/

.PHONY: deb
