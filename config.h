#ifndef CONFIG_H
#define CONFIG_H

/* CHANGE THIS! This is the path for the SQLite DB. */
#define DB_PATH "/var/www/data/ksync.sqlite"
/* Permissions for the SQLite DB. Defaults to 600. See chmod(2) manpages */
#define DB_PERMS S_IRUSR | S_IWUSR
/* Usernames/password lengths must be less than this amount */
#define MAX_USERPASS_LEN 128
/* Make this 0 to disable registrations */
#define REGISTRATIONS_ALLOWED 1

#endif
