# ft_ping
Minimalistic inetutils-ping(1) implementation

## Supported options

- `-f` — packet flood; currently kind of buggy
- `-d` — enable SO_DEBUG option on socket
- `-v` — verbose mode, print information on packet errors
- `-q` — quiet, only print header and summary; works with `-v`
- `--ttl <ttl>` — set IP Time to Live
