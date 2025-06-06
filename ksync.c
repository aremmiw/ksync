#define _XOPEN_SOURCE 700
#define _POSIX_C_SOURCE 200809L

#include "config.h"
#include "db.h"

#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <syslog.h>
#include <time.h>

#include <cjson/cJSON.h>
#include <kcgi.h>

#define PROGRAM_NAME "ksync"

static void respcode(struct kreq *req, enum khttp http);
static void kindex(struct kreq *req);
static void kusers(struct kreq *req);
static void ksyncs(struct kreq *req);
static void khealthcheck(struct kreq *req);
static void get_auth_headers(char **un, char **pw, struct khead *k, int reqsz);
static char *get_json_message(char *key, char *value);
static void put_json_message(char *key, char *value, struct kreq *req, enum khttp http);

typedef	void (*disp) (struct kreq *);

static const struct kvalid emptykey[] = {{NULL, ""}};

enum pages
{
	PAGE_INDEX,
	PAGE_USERS,
	PAGE_SYNCS,
	PAGE_HEALTHCHECK,
	PAGE__MAX,
};

static const disp disps[PAGE__MAX] =
{
	kindex,		/* PAGE_INDEX */
	kusers,		/* PAGE_USERS */
	ksyncs,		/* PAGE_SYNCS */
	khealthcheck,	/* PAGE_HEALTHCHECK */
};

const char *const pages[PAGE__MAX] =
{
	"index",
	"users",
	"syncs",
	"healthcheck",
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

	openlog(PROGRAM_NAME, LOG_CONS | LOG_PID, LOG_USER);

	if (khttp_fcgi_init(&fcgi, emptykey, 1, pages, PAGE__MAX, PAGE_INDEX) != KCGI_OK)
	{
		syslog(LOG_ERR, "failed to init fastcgi");
		return 1;
	}

	if (init_sqlitedb(DB_PATH) != 0)
	{
		close_sqlitedb();
		return 1;
	}

	while (khttp_fcgi_parse(fcgi, &req) == KCGI_OK)
	{
		if (req.method != KMETHOD_GET
		 && req.method != KMETHOD_POST
		 && req.method != KMETHOD_PUT) {
			respcode(&req, KHTTP_405);
		}
		else if (req.page == PAGE__MAX) {
			put_json_message("message", "Invalid page", &req, KHTTP_404);
		}
		else {
			(*disps[req.page])(&req);
		}
		khttp_free(&req);
	}

	khttp_fcgi_free(fcgi);
	close_sqlitedb();

	return 0;
}

static void respcode(struct kreq *req, enum khttp http)
{
	enum kmime mime = KMIME_APP_JSON;

	if (req->page == PAGE_INDEX) {
		mime = KMIME_TEXT_HTML;
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
	if (req->method == KMETHOD_POST && strcmp(req->fullpath, "/users/create") == 0 && req->fieldsz)
	{
		if (!REGISTRATIONS_ALLOWED)
		{
			put_json_message("message", "Registrations disabled", req, KHTTP_402);
			return;
		}

		const cJSON *username = NULL;
		const cJSON *password = NULL;
		cJSON *userpass_json = cJSON_Parse(req->fields[0].val);

		if (userpass_json == NULL)
		{
			put_json_message("message", "Bad request", req, KHTTP_400);
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
				if (create_user(un, pw) == 0) {
					put_json_message("username", un, req, KHTTP_201);
				}
				else {
					put_json_message("message", "Error registering account", req, KHTTP_500);
				}
				break;
			case LOGIN_SUCCESSFUL:
			case LOGIN_FAILURE:
				put_json_message("message", "Username is already registered", req, KHTTP_402);
				break;
			case LOGIN_ERROR:
				put_json_message("message", "Internal server error", req, KHTTP_500);
				break;
			default:
				put_json_message("message", "Bad request", req, KHTTP_400);
				break;
			}
		}
		else {
			put_json_message("message", "Bad request", req, KHTTP_400);
		}
		cJSON_Delete(userpass_json);
	}
	else if (req->method == KMETHOD_GET && strcmp("/users/auth", req->fullpath) == 0)
	{
		char *un = NULL;
		char *pw = NULL;

		get_auth_headers(&un, &pw, req->reqs, req->reqsz);
		int login_code = check_user(un, pw);

		switch (login_code) {
		case LOGIN_SUCCESSFUL:
			put_json_message("authorized", "OK", req, KHTTP_200);
			break;
		case NO_USER_EXISTS:
		case LOGIN_FAILURE:
			put_json_message("message", "Unauthorized", req, KHTTP_401);
			break;
		case LOGIN_ERROR:
			put_json_message("message", "Internal server error", req, KHTTP_500);
			break;
		default:
			put_json_message("message", "Bad request", req, KHTTP_400);
			break;
		}
	}
	else {
		put_json_message("message", "Bad request", req, KHTTP_400);
	}
}

static void ksyncs(struct kreq *req)
{
	char *un = NULL;
	char *pw = NULL;

	get_auth_headers(&un, &pw, req->reqs, req->reqsz);
	int login_code = check_user(un, pw);

	switch (login_code) {
	case LOGIN_SUCCESSFUL:
		break;
	case NO_USER_EXISTS:
	case LOGIN_FAILURE:
		put_json_message("message", "Unauthorized", req, KHTTP_401);
		break;
	case LOGIN_ERROR:
		put_json_message("message", "Internal server error", req, KHTTP_500);
		break;
	default:
		put_json_message("message", "Bad request", req, KHTTP_400);
		break;
	}

	if (login_code != LOGIN_SUCCESSFUL) {
		return;
	}

	if (req->method == KMETHOD_PUT && strcmp(req->fullpath, "/syncs/progress") == 0 && req->fieldsz)
	{
		cJSON *document_json = cJSON_Parse(req->fields[0].val);
		const cJSON *p[DK_MAX];
		Doc d;
		d.timestamp = time(NULL);

		if (document_json == NULL)
		{
			cJSON_Delete(document_json);
			put_json_message("message", "Bad request", req, KHTTP_400);
			return;
		}

		for (int pnum = 0; pnum < DK_MAX; pnum++)
		{
			p[pnum] = cJSON_GetObjectItemCaseSensitive(document_json, document_keys[pnum]);

			if ((pnum == PERCENTAGE_E && !cJSON_IsNumber(p[pnum]))
			 || (pnum != PERCENTAGE_E && (!cJSON_IsString(p[pnum]) || p[pnum]->valuestring == NULL)))
			{
				cJSON_Delete(document_json);
				put_json_message("message", "Bad request", req, KHTTP_400);
				return;
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
				char *json_message = cJSON_PrintUnformatted(update_out);
				khttp_puts(req, json_message);
				free(json_message);
			}
			else {
				put_json_message("message", "Error adding document to the DB", req, KHTTP_500);
			}
			cJSON_Delete(update_out);
		}
		else {
			put_json_message("message", "Error adding document to the DB", req, KHTTP_500);
		}

		cJSON_Delete(document_json);
	}
	else if (req->method == KMETHOD_GET && strncmp(req->fullpath, "/syncs/progress/", 16) == 0)
	{
		char *docname = strrchr(req->fullpath, '/');
		docname++;

		if (*docname != '\0')
		{
			char *message = get_document(un, docname);
			respcode(req, KHTTP_200);
			khttp_puts(req, message);
			free(message);
		}
		else {
			put_json_message("message", "Bad request", req, KHTTP_400);
		}
	}
	else {
		put_json_message("message", "Bad request", req, KHTTP_400);
	}
}

static void khealthcheck(struct kreq *req)
{
	respcode(req, KHTTP_200);
	khttp_puts(req, "{\"state\":\"OK\"}");
}

static void get_auth_headers(char **un, char **pw, struct khead *k, int reqsz)
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

static char *get_json_message(char *key, char *value)
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

static void put_json_message(char *key, char *value, struct kreq *req, enum khttp http)
{
	char *json_message = get_json_message(key, value);
	respcode(req, http);
	khttp_puts(req, json_message);
	free(json_message);
}
