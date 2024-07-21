#define _XOPEN_SOURCE 700
#define _POSIX_C_SOURCE 200809L

#include "config.h"

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>

#include <cjson/cJSON.h>
#include <kcgi.h>
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

static void respcode(struct kreq *req, enum khttp http);

static void kindex(struct kreq *req);
static void kusers(struct kreq *req);
static void ksyncs(struct kreq *req);

int init_sqlitedb(char *dbpath);
int create_user(char *username, char *password);
int check_user(char *username, char *password);
int update_document(char *username, Doc d);
char *get_document(char *username, char *docname);

char *get_json_message(char *key, char *value);
void get_auth_headers(char **un, char **pw, struct khead *k, int reqsz);

typedef	void (*disp) (struct kreq *);

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

sqlite3 *db;
sqlite3_stmt *stmts[STMT_TOTAL] = {NULL};

static const struct kvalid emptykey[] = {{NULL, ""}};

enum pages
{
	PAGE_INDEX,
	PAGE_USERS,
	PAGE_SYNCS,
	PAGE__MAX,
};

static const disp disps[PAGE__MAX] =
{
	kindex, /* PAGE_INDEX */
	kusers, /* PAGE_USERS */
	ksyncs, /* PAGE_SYNCS */
};

const char *const pages[PAGE__MAX] =
{
	"index",
	"users",
	"syncs",
};


enum document_enum
{
	DOCUMENT_E,
	PROGRESS_E,
	PERCENTAGE_E,
	DEVICE_E,
	DEVICE_ID_E,
	DK_MAX,
};

const char *const document_keys[DK_MAX] =
{
	"document",
	"progress",
	"percentage",
	"device",
	"device_id",
};

int main(void)
{
	struct kreq req;
	struct kfcgi *fcgi;

	if (khttp_fcgi_init(&fcgi, emptykey, 1, pages, PAGE__MAX, PAGE_INDEX) != KCGI_OK) {
		return 1;
	}

	if (init_sqlitedb(DB_PATH) != 0) {
		return 1;
	}

	while (khttp_fcgi_parse(fcgi, &req) == KCGI_OK) {
		if (KMETHOD_GET != req.method
		 && KMETHOD_POST != req.method
		 && KMETHOD_PUT != req.method) {
			respcode(&req, KHTTP_405);
		}
		else if (PAGE__MAX == req.page) {
			respcode(&req, KHTTP_404);
			char *json_message = get_json_message("message", "Invalid page");
			khttp_puts(&req, json_message);
			free(json_message);
		}
		else {
			(*disps[req.page])(&req);
		}
		khttp_free(&req);
	}

	khttp_fcgi_free(fcgi);

	for (int snum = 0; snum < STMT_TOTAL; sqlite3_finalize(stmts[snum++]));
	sqlite3_close(db);

	return 0;
}

static void respcode(struct kreq *req, enum khttp http)
{
	enum kmime mime;

	if (KMIME__MAX == (mime = req->mime)) {
		mime = KMIME_APP_JSON;
	}

	khttp_head(req, kresps[KRESP_STATUS], "%s", khttps[http]);
	khttp_head(req, kresps[KRESP_CONTENT_TYPE], "%s", kmimetypes[mime]);
	khttp_body(req);
}

static void kindex(struct kreq *req)
{
	respcode(req, KHTTP_200);
	khttp_puts(req, "ksync!");
}

static void kusers(struct kreq *req)
{
	char *json_message = NULL;
	if (KMETHOD_POST == req->method && strcmp(req->fullpath, "/users/create") == 0 && req->fieldsz)
	{
		const cJSON *username = NULL;
		const cJSON *password = NULL;
		cJSON *userpass_json = cJSON_Parse(req->fields[0].val);

		if (userpass_json == NULL)
		{
			respcode(req, KHTTP_400);
			khttp_puts(req, "Bad request");
			cJSON_Delete(userpass_json);
			return;
		}

		username = cJSON_GetObjectItemCaseSensitive(userpass_json, "username");
		password = cJSON_GetObjectItemCaseSensitive(userpass_json, "password");

		if (cJSON_IsString(username) && username->valuestring != NULL
		 && cJSON_IsString(password) && password->valuestring != NULL)
		{
			char *un = username->valuestring;
			char *pw = password->valuestring;
			int login_code = check_user(un, pw);

			switch (login_code) {
			case NO_USER_EXISTS:
				if (create_user(un, pw) == 0)
				{
					respcode(req, KHTTP_201);
					json_message = get_json_message("username", un);
				}
				else
				{
					respcode(req, KHTTP_500);
					json_message = get_json_message("message", "Error registering account");
				}
				break;
			case LOGIN_SUCCESSFUL:
			case LOGIN_FAILURE:
				respcode(req, KHTTP_402);
				json_message = get_json_message("message", "Username is already registered");
				break;
			default:
				respcode(req, KHTTP_400);
				json_message = get_json_message("message", "Bad request");
				break;
			}
		}
		cJSON_Delete(userpass_json);
	}
	else if (KMETHOD_GET == req->method && strcmp("/users/auth", req->fullpath) == 0)
	{
		char *un = NULL;
		char *pw = NULL;
		get_auth_headers(&un, &pw, req->reqs, req->reqsz);

		int login_code = check_user(un, pw);

		switch (login_code) {
		case LOGIN_SUCCESSFUL:
			respcode(req, KHTTP_200);
			json_message = get_json_message("authorized", "OK");
			break;
		case NO_USER_EXISTS:
		case LOGIN_FAILURE:
			respcode(req, KHTTP_401);
			json_message = get_json_message("message", "Unauthorized");
			break;
		default:
			respcode(req, KHTTP_400);
			json_message = get_json_message("message", "Bad request");
			break;
		}
	}
	else
	{
		respcode(req, KHTTP_400);
		json_message = get_json_message("message", "Bad request");
	}
	khttp_puts(req, json_message);
	free(json_message);
}

static void ksyncs(struct kreq *req)
{
	char *json_message = NULL;
	char *un = NULL;
	char *pw = NULL;

	get_auth_headers(&un, &pw, req->reqs, req->reqsz);
	int login_code = check_user(un, pw);

	switch (login_code) {
	case LOGIN_SUCCESSFUL:
		break;
	case NO_USER_EXISTS:
	case LOGIN_FAILURE:
		respcode(req, KHTTP_401);
		json_message = get_json_message("message", "Unauthorized");
		break;
	default:
		respcode(req, KHTTP_400);
		json_message = get_json_message("message", "Bad request");
		break;
	}

	if (login_code != LOGIN_SUCCESSFUL) {
		goto login_end;
	}

	if (KMETHOD_PUT == req->method && strcmp(req->fullpath, "/syncs/progress") == 0 && req->fieldsz)
	{
		cJSON *document_json = cJSON_Parse(req->fields[0].val);
		const cJSON *p[DK_MAX];
		Doc d;
		d.timestamp = time(NULL);

		if (document_json == NULL)
		{
			respcode(req, KHTTP_400);
			json_message = get_json_message("message", "Bad request");
			cJSON_Delete(document_json);
			goto login_end;
		}

		for (int pnum = 0; pnum < DK_MAX; pnum++)
		{
			p[pnum] = cJSON_GetObjectItemCaseSensitive(document_json, document_keys[pnum]);

			if ((pnum == PERCENTAGE_E && !cJSON_IsNumber(p[pnum]))
			 || (pnum != PERCENTAGE_E && (!cJSON_IsString(p[pnum]) || p[pnum]->valuestring == NULL)))
			{
				respcode(req, KHTTP_400);
				json_message = get_json_message("message", "Bad request");
				cJSON_Delete(document_json);
				goto login_end;
			}

			switch (pnum) {
			case DOCUMENT_E:
				d.document = p[pnum]->valuestring;
				break;
			case PROGRESS_E:
				d.progress = p[pnum]->valuestring;
				break;
			case PERCENTAGE_E:
				d.percentage = p[pnum]->valuedouble;
				break;
			case DEVICE_E:
				d.device = p[pnum]->valuestring;
				break;
			case DEVICE_ID_E:
				d.device_id = p[pnum]->valuestring;
				break;
			}
		}

		if (update_document(un, d) == 0)
		{
			cJSON *update_out = cJSON_CreateObject();

			if (cJSON_AddStringToObject(update_out, "document", d.document) != NULL
			 && cJSON_AddNumberToObject(update_out, "timestamp", d.timestamp) != NULL)
			{
				respcode(req, KHTTP_200);
				json_message = cJSON_PrintUnformatted(update_out);
			}
			else
			{
				respcode(req, KHTTP_500);
				json_message = get_json_message("message", "Error adding document to the DB");
			}
			cJSON_Delete(update_out);
		}
		else
		{
			respcode(req, KHTTP_500);
			json_message = get_json_message("message", "Error adding document to the DB");
		}

		cJSON_Delete(document_json);
	}
	else if (KMETHOD_GET == req->method && strncmp(req->fullpath, "/syncs/progress/", 16) == 0)
	{
		char *docname = strrchr(req->fullpath, '/');
		docname++;

		if (*docname != '\0')
		{
			respcode(req, KHTTP_200);
			json_message = get_document(un, docname);
		}
		else
		{
			respcode(req, KHTTP_400);
			json_message = get_json_message("message", "Bad request");
		}
	}
	else
	{
		respcode(req, KHTTP_400);
		json_message = get_json_message("message", "Bad request");
	}

	login_end:
		khttp_puts(req, json_message);
		free(json_message);
}

int init_sqlitedb(char *dbpath)
{
	if (sqlite3_open(dbpath, &db) != SQLITE_OK)
	{
		sqlite3_close(db);
		return 1;
	}

	const char *init_db = "CREATE TABLE IF NOT EXISTS users(username TEXT, password TEXT, UNIQUE(username)); "
			      "CREATE TABLE IF NOT EXISTS progress(username TEXT, document TEXT, progress TEXT, percentage REAL, device TEXT, device_id TEXT, timestamp DATETIME, UNIQUE(username, document)); ";
	char *errmsg = NULL;

	if (sqlite3_exec(db, init_db, 0, 0, &errmsg) != SQLITE_OK)
	{
		sqlite3_free(errmsg);
		sqlite3_close(db);
		return 1;
	}
	chmod(dbpath, S_IRUSR | S_IWUSR);

	return 0;
}

int create_user(char *username, char *password)
{
	int statement_status;
	if (strlen(username) <= 0 || strlen(password) <= 0
	 || strlen(username) > MAX_USERPASS_LEN || strlen(password) > MAX_USERPASS_LEN) {
		return 1;
	}

	if (stmts[INSERTUSER_STMT] == NULL) {
		sqlite3_prepare_v2(db, "INSERT INTO users (username, password) VALUES (?1, ?2);", -1, &stmts[INSERTUSER_STMT], 0);
	}

	sqlite3_bind_text(stmts[INSERTUSER_STMT], 1, username, -1, SQLITE_TRANSIENT);
	sqlite3_bind_text(stmts[INSERTUSER_STMT], 2, password, -1, SQLITE_TRANSIENT);

	sqlite3_step(stmts[INSERTUSER_STMT]);
	statement_status = sqlite3_reset(stmts[INSERTUSER_STMT]);

	if (statement_status != SQLITE_OK) {
		return 1;
	}
	return 0;
}

int check_user(char *username, char *password)
{
	int statement_status, retcode;
	char *spw = NULL;

	if (username == NULL || password == NULL
	 || strlen(username) <= 0 || strlen(password) <= 0) {
		return LOGIN_ERROR;
	}
	if (strlen(username) > MAX_USERPASS_LEN || strlen(password) > MAX_USERPASS_LEN) {
		return USERPASS_TOO_LONG;
	}

	if (stmts[CHECKUSER_STMT] == NULL) {
		sqlite3_prepare_v2(db, "SELECT password FROM users WHERE username=?1;", -1, &stmts[CHECKUSER_STMT], 0);
	}

	sqlite3_bind_text(stmts[CHECKUSER_STMT], 1, username, -1, SQLITE_TRANSIENT);

	statement_status = sqlite3_step(stmts[CHECKUSER_STMT]);

	switch(statement_status) {
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
	default:
		retcode = LOGIN_ERROR;
		break;
	}
	sqlite3_reset(stmts[CHECKUSER_STMT]);
	return retcode;
}

int update_document(char *username, Doc d)
{	// TODO: modify SQL DB to handle usernames case-insensitively
	char *zsql = "INSERT INTO progress (username, document, progress, percentage, device, device_id, timestamp) "
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

	sqlite3_step(stmts[UPDATEDOC_STMT]);

	if (sqlite3_reset(stmts[UPDATEDOC_STMT]) != SQLITE_OK) {
		return 1;
	}
	return 0;
}

char *get_document(char *username, char *docname)
{
	char *zsql = "SELECT document, progress, percentage, device, device_id, timestamp FROM progress "
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

	if (sqlite3_step(stmts[GETDOC_STMT]) == SQLITE_ROW)
	{
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
	}

	rstring = cJSON_PrintUnformatted(jresponse);

	cJSON_Delete(jresponse);
	sqlite3_reset(stmts[GETDOC_STMT]);
	return rstring;
}

char *get_json_message(char *key, char *value)
{
	if (key == NULL || value == NULL) {
		return NULL;
	}

	char *rstring = NULL;
	cJSON *jresponse = cJSON_CreateObject();

	if (jresponse != NULL && cJSON_AddStringToObject(jresponse, key, value) != NULL) {
		rstring = cJSON_PrintUnformatted(jresponse);
	}

	cJSON_Delete(jresponse);
	return rstring;
}

void get_auth_headers(char **un, char **pw, struct khead *k, int reqsz)
{
	for (int i = 0; i < reqsz; i++)
	{
		if (strcasecmp(k->key, "X-Auth-User") == 0) {
			*un = k->val;
		}
		else if (strcasecmp(k->key, "X-Auth-Key") == 0) {
			*pw = k->val;
		}

		if (*un != NULL && *pw != NULL) {
			break;
		}
		k++;
	}
}
