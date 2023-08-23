# NetKraken

NetKraken is a Network connectivity tester inspired by `nc`, `ncat` and the `netcat`s 
of the world. 
 git status
Goals:
 - Cross platform support, with Windows as a first class citizen
 - Async

This project is a work in progress.

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
  -r, --repeat <REPEAT>      Repeat count (0 for infinite) [default: 4]
      --src-addr <SRC_ADDR>  Source IP Address [default: 0.0.0.0]
      --src-port <SRC_PORT>  Source port (0 detects random unused high port between 1024-65534) [default: 0]
  -t, --timeout <TIMEOUT>    Connection timeout (in milliseconds) [default: 5000]
  -j, --json                 Log to file in JSON format
  -s, --syslog               Log to file in SYSLOG format
  -q, --quiet                Silence terminal output
  -l, --listen               Listen as a server
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

