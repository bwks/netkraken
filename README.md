# NetKraken

NetKraken is a Network connectivity tester inspired by `nc`, `ncat` and the `netcat`s
of the world.

> # 🚧 work in progress 🚧

## Goals
 1) Rapidly prove which of the trinity of evil (Network/Firewall/DNS) is causing connectivity issues
 2) Async all the things for massive concurrency
 3) Cross platform support, with Windows as a first class citizen

## Current Features
 - TCP/UDP Client/Server
 - HTTP Client
 - DNS Client
 - Asynchronous servers allowing for large amounts of client connections
 - Asynchronous clients allow for simultaneous connections to multiple destinations

## Planned Features
 - HTTP Server
 - TCP/UDP traceroute
 - Latency, Jitter, Bandwidth measurement

## Installation
Install the package for your system from the github release page [here](https://github.com/bwks/netkraken/releases)

## Usage
```
nk --help
NetKraken - Cross platform network connectivity tester

Usage: nk <COMMAND>

Commands:
  config  Generate a NetKraken config
  dns     DNS connection
  http    HTTP connection
  https   HTTP connection
  tcp     TCP connection
  udp     UDP connection
  help    Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

## Testing

Using [ncat](https://nmap.org/ncat/) as a server.
### TCP Server
```
ncat -l -k -v 127.0.0.1 8080 --sh-exec "echo ''"
```

### UDP Server
```
ncat -l -u -k -v 127.0.0.1 8080 --sh-exec "echo ''"
```


### ICMP

```
Operation not permitted (os error 1)
```

```
sudo setcap cap_net_bind_service,cap_net_admin,cap_net_raw+eip ./target/debug/nk
```