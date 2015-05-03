# Client Authorization Manager (CAM)

This code was tested on Debian Wheezy (GCC 4.7.2) and Arch Linux (GCC xyz)

## Prerequisites
* openssl
* [jansson](http://www.digip.org/jansson/) JSON-Library (Debian package: ```libjansson4```)
* uriparser (Debian package: ```liburiparser-dev```)
* libcurl
* tinydtls (tested against commit: ```#4a739c2e90eef3c758642e707514614a133576dd```)
* libcoap (branch: ```dcaf```)


## Configuration
No configuration options for cam

## Compile and Run

```
$ make
$ cd build
$ ./cam
```

For further instructions see "Anhang C"
