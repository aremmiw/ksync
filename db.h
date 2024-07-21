#ifndef DB_H
#define DB_H

#include <sqlite3.h>

typedef struct Doc
{
	char *document;
	char *progress;
	double percentage;
	char *device;
	char *device_id;
	long timestamp;
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
	NO_USER_EXISTS,
	USERPASS_TOO_LONG,
};

extern sqlite3 *db;
extern sqlite3_stmt *stmts[STMT_TOTAL];

int init_sqlitedb(char *dbpath);
int create_user(char *username, char *password);
int check_user(char *username, char *password);
int update_document(char *username, Doc d);
char *get_document(char *username, char *docname);

#endif
