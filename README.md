# ksync

ksync is a FastCGI [KOReader](https://github.com/koreader/koreader) sync server implementation written in C with kcgi and SQLite.

It's an alternative to [koreader-sync-server](https://github.com/koreader/koreader-sync-server) and is used for syncing reading progress between KOReader devices.

## dependencies
* [kcgi](https://github.com/kristapsdz/kcgi)
* [SQLite](https://www.sqlite.org/)
* [cJSON](https://github.com/DaveGamble/cJSON)

You may need to run `ldconfig` as root before starting `ksync`.

## building
Change `DB_PATH` in `config.h` to where you want the SQLite database file to be.  

Run `make` which will output a FastCGI executable `ksync`.

## usage
Make sure that the user running `ksync` has permissions to `DB_PATH`, and that the directory exists.

lighttpd and Apache can create a Unix socket for `ksync` without needing any additional programs.  
The webserver user will need permissions to the socket directory.

Example lighttpd config
```
# The fastcgi module must be enabled, check your lighttpd config
fastcgi.server = (
  "/ksync" => ((
    "bin-path" => "/path/to/ksync",
    "socket" => "/var/run/lighttpd/ksync.sock",
    "check-local" => "disable",
    "max-procs" => 2,
  ))
)
```

For nginx or OpenBSD httpd you will need to use a program like [spawn-fcgi](https://github.com/lighttpd/spawn-fcgi) or [kfcgi](https://kristaps.bsd.lv/kcgi/kfcgi.8.html)

Example nginx config
```
location ^~ /ksync/ {
    include fastcgi_params;
    fastcgi_split_path_info ^(/ksync)(/.+)$;
    fastcgi_param PATH_INFO $fastcgi_path_info;
    fastcgi_pass unix:/var/run/ksync.sock;
}
```
