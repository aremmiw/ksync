# ksync

FastCGI KOReader sync server written in C with kcgi and SQLite.

## dependencies
* [kcgi](https://github.com/kristapsdz/kcgi)
* [SQLite](https://www.sqlite.org/)
* [cJSON](https://github.com/DaveGamble/cJSON)

## building
Change `DB_PATH` in `config.h` to where you want the SQLite database file to be.  
The user running `ksync` should have permissions to that path.

Run `make` which will output a FastCGI executable `ksync`.

## usage
lighttpd and Apache will be able to use `ksync` directly.

Example lighttpd config
```
fastcgi.server = (
  "/ksync" => ((
    "bin-path" => "/path/to/ksync",
    "socket" => "/var/run/ksync.sock",
    "check-local" => "disable",
    "max-procs" => 2,
  ))
)
```

For nginx you will need to use a program like [spawn-fcgi](https://github.com/lighttpd/spawn-fcgi) and adjust `fastcgi_pass` accordingly.
