#ifndef DB_H
#define DB_H

#include <stdint.h>

typedef struct Doc
{
	char *document;
	char *progress;
	double percentage;
	char *device;
	char *device_id;
	int64_t timestamp;
} Doc;

enum sql_stmts
{
	CHECKUSER_STMT,
	INSERTUSER_STMT,
	UPDATEDOC_STMT,
	GETDOC_STMT,
	STMT_TOTAL,
};

enum login_types
{
	LOGIN_SUCCESSFUL,
	LOGIN_FAILURE,
	LOGIN_ERROR,
	INVALID_LOGIN,
	NO_USER_EXISTS,
	USERPASS_TOO_LONG,
};

int init_sqlitedb(char *dbpath);
void close_sqlitedb(void);
int create_user(char *username, char *password);
int check_user(char *username, char *password);
int update_document(char *username, Doc d);
char *get_document(char *username, char *docname);

#endif
