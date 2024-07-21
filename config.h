#ifndef CONFIG_H
#define CONFIG_H

/* CHANGE THIS! This is the path for the SQLite DB. */
#define DB_PATH "/var/www/data/ksync.sqlite"
/* Usernames/password lengths must be less than this amount */
#define MAX_USERPASS_LEN 128+1
/* Make this 0 to disable registrations */
#define REGISTRATIONS_ALLOWED 1

#endif
