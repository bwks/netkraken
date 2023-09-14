# NetKraken

NetKraken is a Network connectivity tester inspired by `nc`, `ncat` and the `netcat`s 
of the world. 

> # 🚧 work in progress 🚧

## Goals
 - Cross platform support, with Windows as a first class citizen
 - All clients and servers have Async support
 - Rapidly prove which of the trinity of evil (Network/Firewall/DNS) is causing connectivity issues

## Current Features
 - TCP/UDP Client/Server 
 - Asynchronous servers allowing for large amounts of client connections
 - Asynchronous clients allow for simultaneous connections to multiple destinations

## Planned Features
 - HTTP Client
 - DNS Client
 - TCP/UDP traceroute
 - Latency, Jitter, Bandwidth measurement

## Installation
Install the package for your system from the github release page [here](https://github.com/bwks/netkraken/releases)

## Usage
```
nk --help
NetKraken - Cross platform network connectivity tester

Usage: nk [OPTIONS] <DST_HOST> <DST_PORT>

Arguments:
  <DST_HOST>  Destination hostname or IP address || Listen address in `-l --listen` mode
  <DST_PORT>  Destination port || Listen port in `-l --listen` mode

Options:
  -d, --dir <DIR>            Logging directory [default: .]
  -f, --file <FILE>          Logging filename [default: nk.log]
  -i, --interval <INTERVAL>  Interval between pings (in milliseconds) [default: 1000]
  -m, --method <METHOD>      Connection Method [default: tcp] [possible values: tcp, udp, icmp, http]
  -r, --repeat <REPEAT>      Repeat count (0 == max == 65535) [default: 4]
  -S, --src-ip <SRC_IP>      Source IP Address [default: 0.0.0.0]
  -P, --src-port <SRC_PORT>  Source port (0 detects random unused high port between 1024-65534) [default: 0]
  -t, --timeout <TIMEOUT>    Connection timeout (in milliseconds) [default: 3000]
  -l, --listen               Listen as a server
  -j, --json                 Log to file in JSON format
  -n, --nk-peer              NetKraken peer messaging
  -q, --quiet                Silence terminal output
  -s, --syslog               Log to file in SYSLOG format
  -h, --help                 Print help
  -V, --version              Print version
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
