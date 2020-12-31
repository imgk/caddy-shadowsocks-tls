# Caddy-Shadowsocks-tls

## Build with xcaddy
```
$ xcaddy build \
    --with github.com/imgk/caddy-shadowsocks-tls
```

## Config
```
{
    "apps": {
        "http": {
            "servers": {
                "": {
                    "routes": [
                        {
                            "handle": [
                                {
                                    "handler": "shadowsocks_tls",
                                    "server": "127.0.0.1:8388",
                                    "users": ["password-1", "password-2"]
                                }
                            ]
                        }
                    ]
                }
            }
        }
    }
}

```
