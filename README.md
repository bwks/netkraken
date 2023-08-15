# Net Kraken

Net Kraken is a Network connectivity tester inspired by `netcat` 
and written in Rust.

Goals:
 - Cross platform, with Windows as a first class citizen
 - Async

Work in progress

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

