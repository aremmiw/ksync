#define _XOPEN_SOURCE 700
#define _POSIX_C_SOURCE 200809L

#include "config.h"
#include "db.h"

#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <syslog.h>

#include <cjson/cJSON.h>
#include <sqlite3.h>

sqlite3 *db;
sqlite3_stmt *stmts[STMT_TOTAL] = {NULL};

int init_sqlitedb(char *dbpath, char **errmsg)
{
	if (sqlite3_open(dbpath, &db) != SQLITE_OK)
	{
		*errmsg = (char*) sqlite3_errmsg(db);
		sqlite3_close(db);
		return 1;
	}

	const char *const init_db = "CREATE TABLE IF NOT EXISTS users(username TEXT COLLATE NOCASE, password TEXT, UNIQUE(username)); "
				    "CREATE TABLE IF NOT EXISTS progress(username TEXT COLLATE NOCASE, document TEXT, progress TEXT, "
				    "percentage REAL, device TEXT, device_id TEXT, timestamp DATETIME, UNIQUE(username, document));";
	if (sqlite3_exec(db, init_db, 0, 0, errmsg) != SQLITE_OK)
	{
		sqlite3_close(db);
		return 1;
	}
	chmod(dbpath, DB_PERMS);

	return 0;
}

int create_user(char *username, char *password)
{
	int retcode;
	if (strlen(username) <= 0 || strlen(password) <= 0
	 || strlen(username) > MAX_USERPASS_LEN || strlen(password) > MAX_USERPASS_LEN) {
		return 1;
	}

	if (stmts[INSERTUSER_STMT] == NULL) {
		sqlite3_prepare_v2(db, "INSERT INTO users (username, password) VALUES (?1, ?2);", -1, &stmts[INSERTUSER_STMT], 0);
	}

	sqlite3_bind_text(stmts[INSERTUSER_STMT], 1, username, -1, SQLITE_TRANSIENT);
	sqlite3_bind_text(stmts[INSERTUSER_STMT], 2, password, -1, SQLITE_TRANSIENT);

	switch (sqlite3_step(stmts[INSERTUSER_STMT])) {
	case SQLITE_DONE:
		retcode = 0;
		break;
	case SQLITE_ERROR:
		syslog(LOG_ERR, "create_user() sqlite error: %s", sqlite3_errmsg(db));
		retcode = 1;
		break;
	default:
		retcode = 1;
		break;
	}
	sqlite3_reset(stmts[INSERTUSER_STMT]);
	return retcode;
}

int check_user(char *username, char *password)
{
	int retcode;
	char *spw = NULL;

	if (username == NULL || password == NULL
	 || strlen(username) <= 0 || strlen(password) <= 0) {
		return INVALID_LOGIN;
	}
	if (strlen(username) > MAX_USERPASS_LEN || strlen(password) > MAX_USERPASS_LEN) {
		return USERPASS_TOO_LONG;
	}

	if (stmts[CHECKUSER_STMT] == NULL) {
		sqlite3_prepare_v2(db, "SELECT password FROM users WHERE username=?1;", -1, &stmts[CHECKUSER_STMT], 0);
	}

	sqlite3_bind_text(stmts[CHECKUSER_STMT], 1, username, -1, SQLITE_TRANSIENT);

	switch (sqlite3_step(stmts[CHECKUSER_STMT])) {
	case SQLITE_ROW:
		spw = (char *) sqlite3_column_text(stmts[CHECKUSER_STMT], 0);
		if (spw != NULL && password != NULL && strcmp(password, spw) == 0) {
			retcode = LOGIN_SUCCESSFUL;
		}
		else {
			retcode = LOGIN_FAILURE;
		}
		break;
	case SQLITE_DONE:
		retcode = NO_USER_EXISTS;
		break;
	case SQLITE_ERROR:
		syslog(LOG_ERR, "check_user() sqlite error: %s", sqlite3_errmsg(db));
		retcode = LOGIN_ERROR;
		break;
	default:
		retcode = LOGIN_ERROR;
		break;
	}
	sqlite3_reset(stmts[CHECKUSER_STMT]);
	return retcode;
}

int update_document(char *username, Doc d)
{
	int retcode;
	const char *const zsql = "INSERT INTO progress (username, document, progress, percentage, device, device_id, timestamp) "
				 "VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7) "
				 "ON CONFLICT (username, document) "
				 "DO UPDATE SET progress=excluded.progress, percentage=excluded.percentage, "
				 "device=excluded.device, device_id=excluded.device_id, timestamp=excluded.timestamp;";

	if (stmts[UPDATEDOC_STMT] == NULL) {
		sqlite3_prepare_v2(db, zsql, -1, &stmts[UPDATEDOC_STMT], 0);
	}

	sqlite3_bind_text(stmts[UPDATEDOC_STMT], 1, username, -1, SQLITE_TRANSIENT);
	sqlite3_bind_text(stmts[UPDATEDOC_STMT], 2, d.document, -1, SQLITE_TRANSIENT);
	sqlite3_bind_text(stmts[UPDATEDOC_STMT], 3, d.progress, -1, SQLITE_TRANSIENT);
	sqlite3_bind_double(stmts[UPDATEDOC_STMT], 4, d.percentage);
	sqlite3_bind_text(stmts[UPDATEDOC_STMT], 5, d.device, -1, SQLITE_TRANSIENT);
	sqlite3_bind_text(stmts[UPDATEDOC_STMT], 6, d.device_id, -1, SQLITE_TRANSIENT);
	sqlite3_bind_int64(stmts[UPDATEDOC_STMT], 7, d.timestamp);

	switch (sqlite3_step(stmts[UPDATEDOC_STMT])) {
	case SQLITE_DONE:
		retcode = 0;
		break;
	case SQLITE_ERROR:
		syslog(LOG_ERR, "update_doc() sqlite error: %s", sqlite3_errmsg(db));
		retcode = 1;
		break;
	default:
		retcode = 1;
		break;
	}
	sqlite3_reset(stmts[UPDATEDOC_STMT]);
	return retcode;
}

char *get_document(char *username, char *docname)
{
	const char *const zsql = "SELECT document, progress, percentage, device, device_id, timestamp FROM progress "
				 "WHERE (username=?1 AND document=?2);";
	char *rstring = NULL;
	cJSON *jresponse = cJSON_CreateObject();
	Doc d;

	if (jresponse == NULL) {
		return NULL;
	}

	if (stmts[GETDOC_STMT] == NULL) {
		sqlite3_prepare_v2(db, zsql, -1, &stmts[GETDOC_STMT], 0);
	}

	sqlite3_bind_text(stmts[GETDOC_STMT], 1, username, -1, SQLITE_TRANSIENT);
	sqlite3_bind_text(stmts[GETDOC_STMT], 2, docname, -1, SQLITE_TRANSIENT);

	switch (sqlite3_step(stmts[GETDOC_STMT])) {
	case SQLITE_ROW:
		d.document = (char *) sqlite3_column_text(stmts[GETDOC_STMT], 0);
		d.progress = (char *) sqlite3_column_text(stmts[GETDOC_STMT], 1);
		d.percentage = sqlite3_column_double(stmts[GETDOC_STMT], 2);
		d.device = (char *) sqlite3_column_text(stmts[GETDOC_STMT], 3);
		d.device_id = (char *) sqlite3_column_text(stmts[GETDOC_STMT], 4);
		d.timestamp = sqlite3_column_int64(stmts[GETDOC_STMT], 5);

		cJSON_AddStringToObject(jresponse, "document", d.document);
		cJSON_AddStringToObject(jresponse, "progress", d.progress);
		cJSON_AddNumberToObject(jresponse, "percentage", d.percentage);
		cJSON_AddStringToObject(jresponse, "device", d.device);
		cJSON_AddStringToObject(jresponse, "device_id", d.device_id);
		cJSON_AddNumberToObject(jresponse, "timestamp", d.timestamp);
		break;
	case SQLITE_ERROR:
		syslog(LOG_ERR, "get_document() sqlite error: %s", sqlite3_errmsg(db));
		break;
	default:
		break;
	}

	rstring = cJSON_PrintUnformatted(jresponse);

	cJSON_Delete(jresponse);
	sqlite3_reset(stmts[GETDOC_STMT]);
	return rstring;
}
