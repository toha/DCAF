# Server Authorization Manager (SAM)

This code was tested on Debian Wheezy (GCC 4.7.2) and Arch Linux (GCC xyz)

## Prerequisites
* openssl
* [jansson](http://www.digip.org/jansson/) JSON-Library (Debian package: ```libjansson4```)
* uriparser (Debian package: ```liburiparser-dev```)
* libcurl
* tinydtls (tested against commit: ```#4a739c2e90eef3c758642e707514614a133576dd```)
* libcoap (branch: ```dcaf```)

## Compile and Run

```
$ make
$ cd build
$ ./sam
```

## Make empty config

```
$ make emptyconf
```

## Make example config (for scenario)

```
$ make exampleconf
```

## Configuration
To configure SAM edit the config files under ```conf/``` before compiling or use the REST api intended for the webinterface.

## Usage
You can use the Client Authorization Manager (CAM) to send ticket request messages to SAM or you can use curl for testing. Use the format specified in [draft-gerdes-ace-dcaf-authorize-00](https://tools.ietf.org/html/draft-gerdes-ace-dcaf-authorize-00)

For further instructions see "Anhang C"
