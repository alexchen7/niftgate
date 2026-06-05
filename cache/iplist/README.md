# iplist cache

This folder is intentionally part of the project so the relay can be deployed
without GitHub access. Populate it before deployment with:

```bash
python3 scripts/update_ip_cache.py
```

The updater downloads selected CIDR text files from `metowolf/iplist` into
`country/`, `special/`, `cncity/`, and `isp/` subfolders. Missing cache data is
not fatal; the relay records `unknown` and can ask the exit node for online
fallback lookup over SSH.
