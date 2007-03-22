/*
 * The contents of this file are subject to the Mozilla Public License
 * Version 1.1(the "License"); you may not use this file except in
 * compliance with the License. You may obtain a copy of the License at
 * http://www.mozilla.org/.
 *
 * Software distributed under the License is distributed on an "AS IS"
 * basis,WITHOUT WARRANTY OF ANY KIND,either express or implied. See
 * the License for the specific language governing rights and limitations
 * under the License.
 *
 * Alternatively,the contents of this file may be used under the terms
 * of the GNU General Public License(the "GPL"),in which case the
 * provisions of GPL are applicable instead of those above.  If you wish
 * to allow use of your version of this file only under the terms of the
 * GPL and not to allow others to use your version of this file under the
 * License,indicate your decision by deleting the provisions above and
 * replace them with the notice and other provisions required by the GPL.
 * If you do not delete the provisions above,a recipient may use your
 * version of this file under either the License or the GPL.
 *
 *  PHP module for Naviserver
 *
 *  Author: Vlad Seryakov <vlad@crystalballinc.com>
 *          based on aolserver module by Sascha Schumann <sascha@schumann.cx>
 */

#define Debug php_Debug
#include "php.h"
#include "zend.h"
#include "php_globals.h"
#include "php_compat.h"
#include "php_variables.h"
#include "php_main.h"
#include "php_ini.h"
#include "ext/standard/php_standard.h"
#include "SAPI.h"

#undef Debug
#include "ns.h"

#ifndef ZTS
#error Naviserver module is only useable in thread-safe mode
#endif

#define ADD_STRING(name,buf) php_register_variable(name, buf, track_vars_array TSRMLS_CC)

typedef struct {
   char *buffer;
   Ns_Conn *conn;
   size_t data_avail;
   size_t data_offset;
} ns_context;

/* This symbol is used by Naviserver to tell the API version we expect */

int Ns_ModuleVersion = 1;

PHP_FUNCTION(getallheaders);
PHP_FUNCTION(ns_eval);
PHP_FUNCTION(ns_log);

static void php_info_naviserver(ZEND_MODULE_INFO_FUNC_ARGS);

static zend_function_entry naviserver_functions[] = {
    PHP_FE(getallheaders, NULL)
    PHP_FE(ns_eval,       NULL)
    PHP_FE(ns_log,        NULL)
    {NULL, NULL, NULL}
};

static zend_module_entry php_naviserver_module = {
    STANDARD_MODULE_HEADER,
    "Naviserver",
    naviserver_functions,
    NULL,
    NULL,
    NULL,
    NULL,
    php_info_naviserver,
    NULL,
    STANDARD_MODULE_PROPERTIES
};

PHP_FUNCTION(getallheaders)
{
    int i;
    Ns_Conn *conn = Ns_GetConn();

    if (conn) {
        array_init(return_value);
        for (i = 0; i < Ns_SetSize(conn->headers); i++) {
            char *key = Ns_SetKey(conn->headers, i);
            char *value = Ns_SetValue(conn->headers, i);
            add_assoc_string(return_value, key, value, 1);
        }
    }
}

PHP_FUNCTION(ns_eval)
{
    zval **script;
    CONST char *result;
    int args = ZEND_NUM_ARGS();
    Tcl_Interp *interp = Ns_GetConnInterp(Ns_GetConn());

    if (args != 1 || zend_get_parameters_ex(args, &script) == FAILURE) {
        WRONG_PARAM_COUNT;
    }
    convert_to_string_ex(script);
    if (Tcl_EvalEx(interp, (*script)->value.str.val, -1, 0) != TCL_OK) {
        result = Ns_TclLogError(interp);
    } else {
        result = Tcl_GetStringResult(interp);
    }
    RETURN_STRING((char*)result, 1);
}

PHP_FUNCTION(ns_log)
{
    zval **mode, **str;
    int severity, args = ZEND_NUM_ARGS();

    if (args < 2 || zend_get_parameters_ex(args, &mode, &str) == FAILURE) {
        WRONG_PARAM_COUNT;
    }
    convert_to_string_ex(mode);
    convert_to_string_ex(str);
    severity = !strcasecmp((*mode)->value.str.val, "Error") ? Error :
               !strcasecmp((*mode)->value.str.val, "Warning") ? Warning :
               !strcasecmp((*mode)->value.str.val, "Debug") ? Debug :
               !strcasecmp((*mode)->value.str.val, "Fatal") ? Fatal : Notice;
    Ns_Log(severity, "%s", (*str)->value.str.val);
}

static int php_ns_startup(sapi_module_struct * sapi_module)
{
    if (php_module_startup(sapi_module, &php_naviserver_module, 1) == FAILURE) {
        return FAILURE;
    } else {
        return SUCCESS;
    }
}

/*
 * php_ns_sapi_ub_write() writes data to the client connection.
 */

static int php_ns_sapi_ub_write(const char *str, uint str_length TSRMLS_DC)
{
    int n;
    uint sent = 0;
    ns_context *ctx = SG(server_context);

    if (!ctx->conn) {
        int size = ctx->buffer ? strlen(ctx->buffer) : 0;
        ctx->buffer = ns_realloc(ctx->buffer, size + str_length + 1);
        strncpy(&(ctx->buffer[size]), str, str_length);
        ctx->buffer[size + str_length] = 0;
        return str_length;
    }

    while (str_length > 0) {
        n = Ns_ConnWrite(ctx->conn, (void *) str, str_length);
        if (n == -1) {
            php_handle_aborted_connection();
        }
        str += n;
        sent += n;
        str_length -= n;
    }
    return sent;
}

/*
 * php_ns_sapi_header_handler() sets a HTTP reply header to be sent to the client.
 */

static int php_ns_sapi_header_handler(sapi_header_struct * sapi_header, sapi_headers_struct * sapi_headers TSRMLS_DC)
{
    ns_context *ctx = SG(server_context);
    char *p, *header_name, *header_content;

    header_name = sapi_header->header;
    header_content = p = strchr(header_name, ':');

    if (ctx->conn != NULL && p != NULL) {
        *p = '\0';
        do { header_content++; } while (*header_content == ' ');
        Ns_ConnCondSetHeaders(ctx->conn, header_name, header_content);
        *p = ':';
    }
    efree(sapi_header->header);
    return 0;
}

/*
 * php_ns_sapi_send_headers() flushes the headers to the client.
 * Called before real content is sent by PHP.
 */

static int php_ns_sapi_send_headers(sapi_headers_struct * sapi_headers TSRMLS_DC)
{
    char *ctype = NULL;
    ns_context *ctx = SG(server_context);

    if (!ctx->conn) {
        return SAPI_HEADER_SENT_SUCCESSFULLY;
    }

    if (Ns_SetIGet(ctx->conn->outputheaders, "Content-Type") == NULL) {
        ctype = "text/html";
    }
    Ns_ConnSetRequiredHeaders(ctx->conn, ctype, -1);
    Ns_ConnFlushHeaders(ctx->conn, SG(sapi_headers).http_response_code);
    return SAPI_HEADER_SENT_SUCCESSFULLY;
}

/*
 * php_ns_sapi_read_post() reads a specified number of bytes from
 * the client. Used for POST/PUT requests.
 */

static int php_ns_sapi_read_post(char *buf, uint count_bytes TSRMLS_DC)
{
    char *data;
    uint max_read;
    ns_context *ctx = SG(server_context);

    if (!ctx->conn || (data = Ns_ConnContent(ctx->conn)) == NULL) {
        return 0;
    }

    max_read = MIN(ctx->data_avail, count_bytes);
    if (max_read) {
        memcpy(buf, data + ctx->data_offset, max_read);
        ctx->data_avail -= max_read;
        ctx->data_offset += max_read;
    }
    return max_read;
}

/*
 * php_ns_sapi_read_cookies() returns the Cookie header from the HTTP request header
 */

static char *php_ns_sapi_read_cookies(TSRMLS_D)
{
    ns_context *ctx = SG(server_context);

    if (!ctx->conn) {
        return NULL;
    }

    return Ns_SetIGet(ctx->conn->headers, "Cookie");
}

static void php_ns_sapi_log_message(char *message)
{
    Ns_Log(Error, "nsphp: %s", message);
}

static void php_info_naviserver(ZEND_MODULE_INFO_FUNC_ARGS)
{
    char buf[512];
    int i, uptime = Ns_InfoUptime();
    ns_context *ctx = SG(server_context);

    if (!ctx->conn) {
        return;
    }

    php_info_print_table_start();
    php_info_print_table_row(2, "SAPI module version", "$Id$");
    php_info_print_table_row(2, "Build date", Ns_InfoBuildDate());
    php_info_print_table_row(2, "Config file path", Ns_InfoConfigFile());
    php_info_print_table_row(2, "Error Log path", Ns_InfoErrorLog());
    php_info_print_table_row(2, "Installation path", Ns_InfoHomePath());
    php_info_print_table_row(2, "Hostname of server", Ns_InfoHostname());
    php_info_print_table_row(2, "Server platform", Ns_InfoPlatform());
    snprintf(buf, 511, "%s/%s", Ns_InfoServerName(), Ns_InfoServerVersion());
    php_info_print_table_row(2, "Server version", buf);
    snprintf(buf, 511, "%d day(s), %02d:%02d:%02d", uptime / 86400, (uptime / 3600) % 24, (uptime / 60) % 60, uptime % 60);
    php_info_print_table_row(2, "Server uptime", buf);
    php_info_print_table_end();

    php_info_print_table_start();
    php_info_print_table_colspan_header(2, "HTTP Request Headers");
    php_info_print_table_row(2, "HTTP Request", ctx->conn->request->line);
    for (i = 0; i < Ns_SetSize(ctx->conn->headers); i++) {
        php_info_print_table_row(2, Ns_SetKey(ctx->conn->headers, i), Ns_SetValue(ctx->conn->headers, i));
    }

    php_info_print_table_colspan_header(2, "HTTP Response Headers");
    for (i = 0; i < Ns_SetSize(ctx->conn->outputheaders); i++) {
        php_info_print_table_row(2, Ns_SetKey(ctx->conn->outputheaders, i), Ns_SetValue(ctx->conn->outputheaders, i));
    }
    php_info_print_table_end();
}

/*
 * php_ns_sapi_register_variables() populates the php script environment
 * with a number of variables. HTTP_* variables are created for
 * the HTTP header data, so that a script can access these.
 */

static void php_ns_sapi_register_variables(zval * track_vars_array TSRMLS_DC)
{
    int i;
    Ns_DString ds;
    ns_context *ctx = SG(server_context);

    if (!ctx->conn) {
        return;
    }

    Ns_DStringInit(&ds);
    for (i = 0; i < Ns_SetSize(ctx->conn->headers); i++) {
        char *key = Ns_SetKey(ctx->conn->headers, i);
        char *value = Ns_SetValue(ctx->conn->headers, i);
        char *p, c;

        Ns_DStringSetLength(&ds, 0);
        Ns_DStringPrintf(&ds, "HTTP_%s", key);
        for (p = ds.string + 5; (c = *p); p++) {
            c = toupper(c);
            if (c < 'A' || c > 'Z') {
                c = '_';
            }
            *p = c;
        }
        ADD_STRING(ds.string, value ? value : "");
    }

    Ns_DStringSetLength(&ds, 0);
    Ns_DStringPrintf(&ds, "%s/%s", Ns_InfoServerName(), Ns_InfoServerVersion());
    ADD_STRING("SERVER_SOFTWARE", ds.string);

    Ns_DStringSetLength(&ds, 0);
    Ns_DStringPrintf(&ds, "HTTP/%1.1f", ctx->conn->request->version);
    ADD_STRING("SERVER_PROTOCOL", ds.string);

    ADD_STRING("REQUEST_METHOD", ctx->conn->request->method);

    if (Ns_ConnHost(ctx->conn)) {
        ADD_STRING("SERVER_NAME", Ns_ConnHost(ctx->conn));
    }
    if (ctx->conn->request->query) {
        ADD_STRING("QUERY_STRING", ctx->conn->request->query);
    }

    ADD_STRING("SERVER_BUILDDATE", Ns_InfoBuildDate());

    ADD_STRING("REMOTE_ADDR", Ns_ConnPeer(ctx->conn));

    Ns_DStringSetLength(&ds, 0);
    Ns_DStringPrintf(&ds, "%d", Ns_InfoBootTime());
    ADD_STRING("SERVER_BOOTTIME", ds.string);

    Ns_DStringSetLength(&ds, 0);
    Ns_DStringPrintf(&ds, "%d", Ns_ConnPeerPort(ctx->conn));
    ADD_STRING("REMOTE_PORT", ds.string);

    Ns_DStringSetLength(&ds, 0);
    Ns_DStringPrintf(&ds, "%d", Ns_ConnPort(ctx->conn));
    ADD_STRING("SERVER_PORT", ds.string);

    Ns_DStringSetLength(&ds, 0);
    Ns_DStringPrintf(&ds, "%d", Ns_ConnContentLength(ctx->conn));
    ADD_STRING("CONTENT_LENGTH", ds.string);

    Ns_DStringSetLength(&ds, 0);
    Ns_DStringPrintf(&ds, "%s", SG(request_info).request_uri);
    if (ctx->conn->request->query) {
        Ns_DStringPrintf(&ds, "?%s", ctx->conn->request->query);
    }
    ADD_STRING("REQUEST_URI", ds.string);

    ADD_STRING("PHP_SELF", SG(request_info).request_uri);
    ADD_STRING("SCRIPT_NAME", SG(request_info).request_uri);
    ADD_STRING("PATH_TRANSLATED", SG(request_info).path_translated);
    ADD_STRING("SCRIPT_FILENAME", SG(request_info).path_translated);
    ADD_STRING("GATEWAY_INTERFACE", "CGI/1.1");

    Ns_DStringSetLength(&ds, 0);
    ADD_STRING("DOCUMENT_ROOT", Ns_PagePath(&ds, Ns_ConnServer(ctx->conn), NULL));

    Ns_DStringFree(&ds);
}

/* this structure is static (as in "it does not change") */

static sapi_module_struct naviserver_sapi_module = {
    "naviserver",
    "Naviserver",

    php_ns_startup,             /* startup */
    php_module_shutdown_wrapper,/* shutdown */

    NULL,                       /* activate */
    NULL,                       /* deactivate */

    php_ns_sapi_ub_write,       /* unbuffered write */
    NULL,                       /* flush */
    NULL,                       /* get uid */
    NULL,                       /* getenv */

    php_error,                  /* error handler */

    php_ns_sapi_header_handler, /* header handler */
    php_ns_sapi_send_headers,   /* send headers handler */
    NULL,                       /* send header handler */

    php_ns_sapi_read_post,      /* read POST data */
    php_ns_sapi_read_cookies,   /* read Cookies */

    php_ns_sapi_register_variables,
    php_ns_sapi_log_message,    /* Log message */
    NULL,                       /* Get request time */

    STANDARD_SAPI_MODULE_PROPERTIES
};

/*
 * The php_ns_request_handler() is called per request and handles everything for one request.
 */

static int php_ns_request_handler(void *context, Ns_Conn * conn)
{
    Ns_DString ds;
    ns_context ctx;
    int status = NS_OK;
    zend_file_handle file_handle = {0};

    TSRMLS_FETCH();

    Ns_DStringInit(&ds);
    Ns_UrlToFile(&ds, Ns_ConnServer(conn), conn->request->url);
    SG(request_info).path_translated = ns_strdup(Ns_DStringValue(&ds));
    Ns_DStringFree(&ds);

    SG(request_info).query_string = conn->request->query;
    SG(request_info).request_uri = conn->request->url;
    SG(request_info).request_method = conn->request->method;
    SG(request_info).proto_num = conn->request->version > 1.0 ? 1001 : 1000;
    SG(request_info).content_length = Ns_ConnContentLength(conn);
    SG(request_info).content_type = Ns_SetIGet(conn->headers, "Content-Type");
    SG(request_info).auth_user = ns_strcopy(Ns_ConnAuthUser(conn));
    SG(request_info).auth_password = ns_strcopy(Ns_ConnAuthPasswd(conn));
    SG(sapi_headers).http_response_code = 200;

    SG(server_context) = &ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.data_avail = SG(request_info).content_length;
    ctx.conn = conn;

    file_handle.type = ZEND_HANDLE_FILENAME;
    file_handle.filename = SG(request_info).path_translated;
    file_handle.free_filename = 0;
    file_handle.opened_path = NULL;

    zend_first_try {
       php_request_startup(TSRMLS_C);
       status = php_execute_script(&file_handle TSRMLS_CC) ? NS_OK : NS_ERROR;
       php_request_shutdown(NULL);
    } zend_catch {
       status = NS_ERROR;
    } zend_end_try();

    ns_free(SG(request_info).path_translated);
    ns_free(SG(request_info).auth_user);
    ns_free(SG(request_info).auth_password);
    return status;
}

/*
 * php_ns_server_shutdown() performs the last steps before the
 * server exits. Shutdowns basic services and frees memory
 */

static void php_ns_server_shutdown(Ns_Time *toPtr, void *context)
{
    naviserver_sapi_module.shutdown(&naviserver_sapi_module);
    sapi_shutdown();
    tsrm_shutdown();
}

/*
 *----------------------------------------------------------------------
 *
 * PHPObjCmd --
 *
 *      Implement the ns_php command.
 *
 * Results:
 *      Standard Tcl result.
 *
 * Side effects:
 *      Depends on command.
 *
 *----------------------------------------------------------------------
 */

static int PHPObjCmd(ClientData arg, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{
    zval *name;
    int status, cmd;
    ns_context ctx;
    zend_file_handle file_handle;

    enum {
        CALL, EVAL, EVALFILE, VERSION
    };
    static CONST char *subcmd[] = {
        "call", "eval", "evalfle", "version",
        NULL
    };

    if (objc < 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "option ?arg ...?");
        return TCL_ERROR;
    }
    status = Tcl_GetIndexFromObj(interp, objv[1], subcmd, "option", 0, &cmd);
    if (status != TCL_OK) {
        return TCL_ERROR;
    }

    TSRMLS_FETCH();
    SG(server_context) = &ctx;
    memset(&ctx, 0, sizeof(ctx));

    switch (cmd) {
    case EVAL:
       if (objc < 3) {
           Tcl_WrongNumArgs(interp, 2, objv, "script");
           status = TCL_ERROR;
           break;
       }
       zend_try {
         if (php_request_startup(TSRMLS_C) != FAILURE) {
             zend_eval_string(Tcl_GetString(objv[2]), NULL, "ns:php" TSRMLS_CC);
             Tcl_AppendResult(interp, ctx.buffer, NULL);
             php_request_shutdown(NULL);
         }
       } zend_end_try();
       break;

    case EVALFILE:
       if (objc < 3) {
           Tcl_WrongNumArgs(interp, 2, objv, "filename");
           status = TCL_ERROR;
           break;
       }
       memset(&file_handle, 0, sizeof(file_handle));
       file_handle.type = ZEND_HANDLE_FILENAME;
       file_handle.filename = Tcl_GetString(objv[2]);
       if (php_request_startup(TSRMLS_C) != FAILURE) {
           php_execute_script(&file_handle TSRMLS_CC);
           Tcl_AppendResult(interp, ctx.buffer, NULL);
           zend_try {
             php_request_shutdown(NULL);
           } zend_end_try();
       }
       break;

    case CALL:
       if (objc < 3) {
           Tcl_WrongNumArgs(interp, 2, objv, "functionname ...");
           status = TCL_ERROR;
           break;
       }
       zend_try {
         if (php_request_startup(TSRMLS_C) != FAILURE) {
             MAKE_STD_ZVAL(name);
             ZVAL_STRING(name, Tcl_GetString(objv[2]), 1);
             call_user_function(CG(function_table), NULL, name, NULL, 0, NULL, 0);
             Tcl_AppendResult(interp, ctx.buffer, NULL);
             zval_ptr_dtor(&name);
             php_request_shutdown(NULL);
         }
       } zend_end_try();
       break;

    case VERSION:
       Tcl_AppendResult(interp, PHP_VERSION, NULL);
       break;
    }
    ns_free(ctx.buffer);
    return status;
}

static int php_ns_command(Tcl_Interp *interp, void *arg)
{
    Tcl_CreateObjCommand(interp, "ns_php", PHPObjCmd, arg, NULL);
    return TCL_OK;
}

/*
 * Ns_ModuleInit() is called by Naviserver once at startup
 *
 * This functions allocates basic structures and initializes basic services.
 */

int Ns_ModuleInit(char *server, char *module)
{
    int i;
    char *path;
    Ns_Set *set;

    tsrm_startup(1, 1, TSRM_ERROR_LEVEL_CORE, NULL);
    sapi_startup(&naviserver_sapi_module);
    sapi_module.startup(&naviserver_sapi_module);

    /* read the configuration */
    path = Ns_ConfigGetPath(server, module, NULL);
    set = Ns_ConfigGetSection(path);

    for (i = 0; set && i < Ns_SetSize(set); i++) {
        char *key = Ns_SetKey(set, i);
        char *value = Ns_SetValue(set, i);

        if (!strcasecmp(key, "map")) {
            Ns_Log(Notice, "Registering PHP for \"%s\"", value);
            Ns_RegisterRequest(server, "GET", value, php_ns_request_handler, NULL, 0, 0);
            Ns_RegisterRequest(server, "POST", value, php_ns_request_handler, NULL, 0, 0);
            Ns_RegisterRequest(server, "HEAD", value, php_ns_request_handler, NULL, 0, 0);
        }
    }

    //Ns_RegisterAtShutdown(php_ns_server_shutdown, 0);

    Ns_TclRegisterTrace(server, php_ns_command, 0, NS_TCL_TRACE_CREATE);

    Ns_Log(Notice, "nsphp: started %s", PHP_VERSION);
    return NS_OK;
}

