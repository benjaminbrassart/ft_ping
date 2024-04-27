# ft_ping
Minimalistic inetutils-ping(1) implementation

## Supported options

- `-f`, `--flood` — packet flood; currently kind of buggy
- `-d`, `--debug` — enable SO_DEBUG option on socket
- `-v`, `--verbose` — verbose mode, print information on packet errors
- `-q`, `--quiet` — quiet, only print header and summary; works with `-v`
- `-s`, `--size` — set ICMP packet data size
- `-V`, `--version` — show version and exit
- `-?`, `--help` — show help message and exit
- `--ttl <ttl>` — set IP Time to Live
