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

#include "ns.h"
#include "nsdb.h"

#define Debug php_Debug
#include "php.h"
#include "zend.h"
#include "php_globals.h"
#include "php_compat.h"
#include "php_variables.h"
#include "php_main.h"
#include "php_ini.h"
#include "ext/standard/php_standard.h"
#include "ext/standard/info.h"
#include "ext/pdo/php_pdo.h"
#include "ext/pdo/php_pdo_driver.h"
#include "zend_exceptions.h"
#include "SAPI.h"

#undef Debug

#ifndef ZTS
#error Naviserver module is only useable in thread-safe mode
#endif

#define ADD_STRING(name,buf)   php_register_variable(name, buf, track_vars_array TSRMLS_CC)
#define STRDUP(s)              (s != NULL ? estrdup(s) : NULL) 

typedef struct {
    char *buffer;
    Ns_Conn *conn;
    size_t data_avail;
    size_t data_offset;
} ns_context;

typedef struct {
    Ns_DbHandle *db;
    Ns_Set *row;
    char *sql;
} ns_pdo_handle;

PHP_FUNCTION(ns_eval);
PHP_FUNCTION(ns_log);
PHP_FUNCTION(ns_header);
PHP_FUNCTION(ns_headers);
PHP_FUNCTION(ns_outputheaders);
PHP_FUNCTION(ns_header);
PHP_FUNCTION(ns_eval);
PHP_FUNCTION(ns_log);
PHP_FUNCTION(ns_info);
PHP_FUNCTION(ns_conn);
PHP_FUNCTION(ns_returnredirect);
PHP_FUNCTION(ns_returndata);
PHP_FUNCTION(ns_returnfile);
PHP_FUNCTION(ns_queryexists);
PHP_FUNCTION(ns_queryget);
PHP_FUNCTION(ns_querygetall);
PHP_FUNCTION(nsv_get);
PHP_FUNCTION(nsv_set);
PHP_FUNCTION(nsv_exists);
PHP_FUNCTION(nsv_incr);
PHP_FUNCTION(nsv_unset);
PHP_FUNCTION(nsv_append);

PHP_MINIT_FUNCTION(pdo_naviserver);
PHP_MSHUTDOWN_FUNCTION(pdo_naviserver);
PHP_MINFO_FUNCTION(pdo_naviserver);
PHP_RSHUTDOWN_FUNCTION(pdo_naviserver);

static Tcl_ObjCmdProc php_ns_tcl_cmd;
static Ns_TclTraceProc php_ns_tcl_init;


static Ns_ThreadArgProc ThreadArgProc;

static int pdo_naviserver_handle_factory(pdo_dbh_t *dbh, zval *driver_options TSRMLS_DC);
static int pdo_naviserver_handle_fetch_error(pdo_dbh_t *dbh, pdo_stmt_t *stmt, zval *info TSRMLS_DC);
static int pdo_naviserver_handle_closer(pdo_dbh_t *dbh TSRMLS_DC);
static int pdo_naviserver_handle_preparer(pdo_dbh_t *dbh, const char *sql, long sql_len, pdo_stmt_t *stmt, zval *driver_options TSRMLS_DC);
static int pdo_naviserver_handle_quoter(pdo_dbh_t *dbh, const char *unquoted, int unquotedlen, char **quoted, int *quotedlen, enum pdo_param_type paramtype TSRMLS_DC);
static long pdo_naviserver_handle_doer(pdo_dbh_t *dbh, const char *sql, long sql_len TSRMLS_DC);
static int pdo_naviserver_stmt_dtor(pdo_stmt_t *stmt TSRMLS_DC);
static int pdo_naviserver_stmt_execute(pdo_stmt_t *stmt TSRMLS_DC);
static int pdo_naviserver_stmt_fetch(pdo_stmt_t *stmt,    enum pdo_fetch_orientation ori, long offset TSRMLS_DC);
static int pdo_naviserver_stmt_describe(pdo_stmt_t *stmt, int colno TSRMLS_DC);
static int pdo_naviserver_stmt_get_col(pdo_stmt_t *stmt, int colno, char **ptr, unsigned long *len, int *caller_frees TSRMLS_DC);

static int php_ns_sapi_ub_write(const char *str, uint str_length TSRMLS_DC);
static int php_ns_sapi_header_handler(sapi_header_struct *sapi_header,
                                      sapi_header_op_enum op,
                                      sapi_headers_struct *sapi_headers TSRMLS_DC);

static int php_ns_sapi_send_headers(sapi_headers_struct *sapi_headers TSRMLS_DC);
static int php_ns_sapi_read_post(char *buf, uint count_bytes TSRMLS_DC);
static char *php_ns_sapi_read_cookies(TSRMLS_D);
static void php_ns_sapi_register_variables(zval *track_vars_array TSRMLS_DC);
static void php_ns_sapi_log_message(char *message TSRMLS_DC);
static void php_ns_sapi_info(ZEND_MODULE_INFO_FUNC_ARGS);
static int php_ns_sapi_startup(sapi_module_struct * sapi_module);
static int php_ns_sapi_request_handler(void *context, Ns_Conn * conn);

/*
 * defined in /usr/local/src/php-5.6.6//main/SAPI.h

 */
static sapi_module_struct naviserver_sapi_module = {
    "naviserver",
    "Naviserver",

    php_ns_sapi_startup,                      /* startup */
    php_module_shutdown_wrapper,              /* shutdown */

    NULL,                                     /* activate */
    NULL,                                     /* deactivate */

    php_ns_sapi_ub_write,                     /* unbuffered write */
    NULL,                                     /* flush */
    NULL,                                     /* stat */
    NULL,                                     /* getenv */

    php_error,                                /* error handler */

    php_ns_sapi_header_handler,               /* header handler */
    php_ns_sapi_send_headers,                 /* send headers handler */
    NULL,                                     /* send header handler */

    php_ns_sapi_read_post,                    /* read POST data */
    php_ns_sapi_read_cookies,                 /* read Cookies */

    php_ns_sapi_register_variables,
    php_ns_sapi_log_message,                  /* log message */
    NULL,                                     /* get request time */

    STANDARD_SAPI_MODULE_PROPERTIES
};


static zend_function_entry naviserver_functions[] = {
    PHP_FE(ns_header,        NULL)
    PHP_FE(ns_eval,          NULL)
    PHP_FE(ns_log,           NULL)
    PHP_FE(ns_headers,       NULL)
    PHP_FE(ns_outputheaders, NULL)
    PHP_FE(ns_info,          NULL)
    PHP_FE(ns_conn,          NULL)
    PHP_FE(ns_returnredirect,NULL)
    PHP_FE(ns_returndata,    NULL)
    PHP_FE(ns_returnfile,    NULL)
    PHP_FE(ns_queryexists,   NULL)
    PHP_FE(ns_queryget,      NULL)
    PHP_FE(ns_querygetall,   NULL)
    PHP_FE(nsv_get,          NULL)
    PHP_FE(nsv_set,          NULL)
    PHP_FE(nsv_exists,       NULL)
    PHP_FE(nsv_incr,         NULL)
    PHP_FE(nsv_unset,        NULL)
    PHP_FE(nsv_append,       NULL)
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
    php_ns_sapi_info,
    NULL,
    STANDARD_MODULE_PROPERTIES
};

static pdo_driver_t pdo_naviserver_driver = {
    PDO_DRIVER_HEADER(naviserver),
    pdo_naviserver_handle_factory
};

static struct pdo_dbh_methods pdo_naviserver_methods = {
    pdo_naviserver_handle_closer,
    pdo_naviserver_handle_preparer,
    pdo_naviserver_handle_doer,
    pdo_naviserver_handle_quoter,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,                               /* last insert */
    pdo_naviserver_handle_fetch_error,  /* fetch error */
    NULL,                               /* get attr */
    NULL,                               /* check liveness */
};

static struct pdo_stmt_methods pdo_naviserver_stmt_methods = {
    pdo_naviserver_stmt_dtor,
    pdo_naviserver_stmt_execute,
    pdo_naviserver_stmt_fetch,
    pdo_naviserver_stmt_describe,
    pdo_naviserver_stmt_get_col,
    NULL,
    NULL,                           /* set attr */
    NULL,                           /* get attr */
    NULL,                           /* meta */
    NULL,                           /* nextrow */
    NULL
};

int Ns_ModuleVersion = 1;

/*
 *----------------------------------------------------------------------
 *
 * Ns_ModuleInit
 *
 *      Called by Naviserver once at startup
 *
 * Results:
 *      NS_OK or NS_ERROR
 *
 * Side effects:
 *      This functions allocates basic structures and initializes basic services.
 *
 *----------------------------------------------------------------------
 */

int Ns_ModuleInit(char *server, char *module)
{
    int i;
    const char *path;
    Ns_Set *set;

    tsrm_startup(1, 1, TSRM_ERROR_LEVEL_INFO, NULL);
    sapi_startup(&naviserver_sapi_module);
    sapi_module.startup(&naviserver_sapi_module);

    php_pdo_register_driver(&pdo_naviserver_driver);

    /*
     * read the configuration
     */
    path = Ns_ConfigGetPath(server, module, (char *)0);
    set = Ns_ConfigGetSection(path);

    for (i = 0; set && i < Ns_SetSize(set); i++) {
        char *key = Ns_SetKey(set, i);
        char *value = Ns_SetValue(set, i);

        if (!strcasecmp(key, "map")) {
            Ns_Log(Notice, "Registering PHP for \"%s\"", value);
            Ns_RegisterRequest(server, "GET", value, php_ns_sapi_request_handler, NULL, 0, 0);
            Ns_RegisterRequest(server, "POST", value, php_ns_sapi_request_handler, NULL, 0, 0);
            Ns_RegisterRequest(server, "HEAD", value, php_ns_sapi_request_handler, NULL, 0, 0);
            Ns_RegisterRequest(server, "PUT", value, php_ns_sapi_request_handler, NULL, 0, 0);
            Ns_RegisterRequest(server, "DELETE", value, php_ns_sapi_request_handler, NULL, 0, 0);
       }
    }

    Ns_TclRegisterTrace(server, php_ns_tcl_init, 0, NS_TCL_TRACE_CREATE);

    Ns_Log(Notice, "nsphp: started %s", PHP_VERSION);
    return NS_OK;
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

static int php_ns_tcl_cmd(ClientData arg, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{
    zval *name, *val;
    int status, cmd;
    ns_context ctx;
    zend_file_handle file_handle;

    enum {
        cmdCALL, cmdEVAL, cmdEVALFILE, cmdVAR, cmdVERSION
    };
    static CONST char *subcmd[] = {
        "call", "eval", "evalfile", "var", "version",
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
    case cmdEVAL:
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

    case cmdEVALFILE:
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

    case cmdCALL:
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

    case cmdVAR:
        if (objc < 3) {
            Tcl_WrongNumArgs(interp, 2, objv, "varname");
            status = TCL_ERROR;
            break;
        }
        zend_try {
            if (php_request_startup(TSRMLS_C) != FAILURE) {
                MAKE_STD_ZVAL(val);
                zend_eval_string(Tcl_GetString(objv[2]), val, "ns:php" TSRMLS_CC);
                convert_to_string_ex(&val);
                Tcl_AppendResult(interp, val->value.str.val, NULL);
                zval_ptr_dtor(&val);
                php_request_shutdown(NULL);
            }
        } zend_end_try();
        break;

    case cmdVERSION:
        Tcl_AppendResult(interp, PHP_VERSION, NULL);
        break;
    }
    ns_free(ctx.buffer);
    return status;
}

static int php_ns_tcl_init(Tcl_Interp *interp, const void *arg)
{
    Tcl_CreateObjCommand(interp, "ns_php", php_ns_tcl_cmd, (ClientData)arg, NULL);
    return TCL_OK;
}

static void ThreadArgProc(Tcl_DString *dsPtr, Ns_ThreadProc proc, const void *arg)
{
    Ns_GetProcInfo(dsPtr, proc, arg);
}

PHP_FUNCTION(ns_headers)
{
    Ns_Conn *conn = Ns_GetConn();

    if (conn) {
        Ns_Set *hdrs = Ns_ConnHeaders(conn);
        
        if (hdrs != NULL) {
            int i;
                
            array_init(return_value);
            for (i = 0; i < Ns_SetSize(hdrs); i++) {
                char *key = Ns_SetKey(hdrs, i);
                char *value = Ns_SetValue(hdrs, i);
                add_assoc_string(return_value, key, value, 1);
            }
        }
    }
}

PHP_FUNCTION(ns_outputheaders)
{
    Ns_Conn *conn = Ns_GetConn();

    if (conn) {
        Ns_Set *hdrs = Ns_ConnOutputHeaders(conn);
        
        if (hdrs != NULL) {
            int i;
            
            array_init(return_value);
            for (i = 0; i < Ns_SetSize(hdrs); i++) {
                char *key = Ns_SetKey(hdrs, i);
                char *value = Ns_SetValue(hdrs, i);
                
                add_assoc_string(return_value, key, value, 1);
            }
        }
    }
}

PHP_FUNCTION(ns_header)
{
    char    *name;
    int      nlen;
    Ns_Conn *conn = Ns_GetConn();

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &name, &nlen) == FAILURE) {
        RETURN_FALSE;
    }
    if (conn) {
        const char *result = Ns_SetIGetValue(Ns_ConnHeaders(conn), name, NULL);
        if (result != NULL) {
            RETURN_STRING((char*)result, 1);
        }
    }
}

PHP_FUNCTION(ns_eval)
{
    char *name;
    int nlen;
    const char *result;
    Tcl_Interp *interp = Ns_GetConnInterp(Ns_GetConn());

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &name, &nlen) == FAILURE) {
        RETURN_FALSE;
    }
    if (Tcl_EvalEx(interp, name, nlen, 0) != TCL_OK) {
        result = Ns_TclLogErrorInfo(interp, "\n(context: php eval)");
    } else {
        result = Tcl_GetStringResult(interp);
    }
    RETURN_STRING((char*)result, 1);
}

PHP_FUNCTION(ns_log)
{
    char *level, *str;
    int llen, slen, severity;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss", &level, &llen, &str, &slen) == FAILURE) {
        RETURN_FALSE;
    }
    severity = !strcasecmp(level, "Error") ? Error :
        !strcasecmp(level, "Warning") ? Warning :
        !strcasecmp(level, "Debug") ? Debug :
        !strcasecmp(level, "Fatal") ? Fatal : Notice;
    Ns_Log(severity, "%s", str);
}

PHP_FUNCTION(ns_info)
{
    char *name;
    const char *result;
    int nlen;
    Ns_DString ds;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &name, &nlen) == FAILURE) {
        RETURN_FALSE;
    }
    static const char *cmds[] = {
        "address", "boottime", "builddate", "threads",
        "config", "home", "hostname", "locks", "log",
        "major", "minor", "name", "nsd", "pageroot", "patchlevel",
        "pid", "platform", "tag", "uptime", "version", "winnt", 0 };
    enum {
        IAddressIdx, IBoottimeIdx, IBuilddateIdx, IThreadsIdx,
        IConfigIdx, IHomeIdx, hostINameIdx, ILocksIdx, ILogIdx,
        IMajorIdx, IMinorIdx, INameIdx, INsdIdx, IPageRootIdx, IPatchLevelIdx,
        IPidIdx, IPlatformIdx, ITagIdx, IUptimeIdx, IVersionIdx, IWinntIdx, INoneIdx
    } opt;

    for (opt = 0; cmds[opt]; opt++) {
        if (!strcmp(cmds[opt], name)) {
            break;
        }
    }

    Ns_DStringInit(&ds);

    switch(opt) {
    case IAddressIdx:
        result = Ns_InfoAddress();
        break;

    case IBoottimeIdx:
        Ns_DStringPrintf(&ds, "%lu", Ns_InfoBootTime());
        result = ds.string;
        break;

    case IBuilddateIdx:
        result = Ns_InfoBuildDate();
        break;

    case IConfigIdx:
        result = (char *)Ns_InfoConfigFile();
        break;

    case IHomeIdx:
        result = (char *)Ns_InfoHomePath();
        break;

    case hostINameIdx:
        result = (char *)Ns_InfoHostname();
        break;

    case ILogIdx:
        result = (char *)Ns_InfoErrorLog();
        break;

    case IMajorIdx:
        Ns_DStringPrintf(&ds, "%d", NS_MAJOR_VERSION);
        result = ds.string;
        break;

    case IMinorIdx:
        Ns_DStringPrintf(&ds, "%d", NS_MINOR_VERSION);
        result = ds.string;
        break;

    case INameIdx:
        result = Ns_InfoServerName();
        break;

    case IPageRootIdx:
        Ns_PagePath(&ds, "", (char *)0);
        result = ds.string;
        break;

    case IPatchLevelIdx:
        result = NS_PATCH_LEVEL;
        break;

    case IPidIdx:
        Ns_DStringPrintf(&ds, "%d", Ns_InfoPid());
        result = ds.string;
        break;

    case IPlatformIdx:
        result = Ns_InfoPlatform();
        break;

    case ILocksIdx:
        Ns_MutexList(&ds);
        result = ds.string;
        break;

    case ITagIdx:
        result = Ns_InfoTag();
        break;

    case IThreadsIdx:
        Ns_ThreadList(&ds, ThreadArgProc);
        result = ds.string;
        break;

    case IUptimeIdx:
        Ns_DStringPrintf(&ds, "%ld", Ns_InfoUptime());
        result = ds.string;
        break;

    case IVersionIdx:
        result = NS_VERSION;
        break;

    case IWinntIdx:
#ifdef _WIN32
        result = "1";
#else
        result = "0";
#endif
        break;

    default:
        result = NULL;
    }

    result = estrdup(result != NULL ? result : "");
    Ns_DStringFree(&ds);
    RETURN_STRING((char*)result, 0);
}

PHP_FUNCTION(ns_conn)
{
    int idx;
    Ns_Conn *conn;
    Tcl_DString ds;
    char *name, *dupl;
    const char *result = NULL;
    int nlen;

    static const char *cmds[] = {
        "authpassword", "authuser", "close", "content", "contentlength",
        /*"copy",*/ "driver", "encoding", "flags", 
        "host", "id", "isconnected", "location", "method",
        "peeraddr", "peerport", "port", "protocol", "query", "request",
        "server", "sock", "start", "status", "url", "urlc", "urlencoding",
        "urlv", "version", 
        0
    };
    enum ISubCmdIdx {
        CAuthPasswordIdx, CAuthUserIdx, CCloseIdx, CContentIdx, CContentLengthIdx,
        /* CCopyIdx,*/ CDriverIdx, CEncodingIdx, CFlagsIdx,
        CHostIdx, CIdIdx, CIsConnectedIdx, CLocationIdx, CMethodIdx,
        CPeerAddrIdx, CPeerPortIdx, CPortIdx, CProtocolIdx, CQueryIdx, CRequestIdx,
        CServerIdx, CSockIdx, CStartIdx, CStatusIdx, CUrlIdx, CUrlcIdx, CUrlEncodingIdx,
        CUrlvIdx, CVersionIdx
    } opt;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &name, &nlen) == FAILURE) {
        RETURN_FALSE;
    }

    for (opt = 0; cmds[opt]; opt++) {
        if (!strcmp(cmds[opt], name)) {
            break;
        }
    }

    conn = Ns_GetConn();

    if (opt != CIsConnectedIdx && conn == NULL) {
        RETURN_FALSE
            }

    Tcl_DStringInit(&ds);
    switch(opt) {
    case CIsConnectedIdx:
        result = conn ? "true" : "false";
        break;
        
    case CUrlvIdx:
        for (idx = 0; idx < conn->request->urlc; idx++) {
            Ns_DStringPrintf(&ds, "%s ",conn->request->urlv[idx]);
        }
        result = ds.string;
        break;

    case CAuthUserIdx:
        result = Ns_ConnAuthUser(conn);
        break;
        
    case CAuthPasswordIdx:
        result = Ns_ConnAuthPasswd(conn);
        break;

    case CContentIdx:
        result = Ns_ConnContent(conn);
        break;
        
    case CContentLengthIdx:
        Ns_DStringPrintf(&ds,"%" PRIuz,conn->contentLength);
        result = ds.string;
        break;

    case CEncodingIdx:
        result = Tcl_GetEncodingName(Ns_ConnGetEncoding(conn));
        break;
    
    case CUrlEncodingIdx:
        result = Tcl_GetEncodingName(Ns_ConnGetUrlEncoding(conn));
        break;
    
    case CPeerAddrIdx:
        result = Ns_ConnPeer(conn);
        break;
    
    case CPeerPortIdx:
        Ns_DStringPrintf(&ds, "%d", Ns_ConnPeerPort(conn));
        result = ds.string;
        break;

    case CRequestIdx:
        result = conn->request->line;
        break;

    case CMethodIdx:
        result = conn->request->method;
        break;

    case CProtocolIdx:
        result = conn->request->protocol;
        break;

    case CHostIdx:
        result = conn->request->host;
        break;
    
    case CPortIdx:
        Ns_DStringPrintf(&ds, "%d", conn->request->port);
        result = ds.string;
        break;

    case CUrlIdx:
        result = conn->request->url;
        break;
    
    case CQueryIdx:
        result = conn->request->query;
        break;
    
    case CUrlcIdx:
        Ns_DStringPrintf(&ds, "%d", conn->request->urlc);
        result = ds.string;
        break;
    
    case CVersionIdx:
        Ns_DStringPrintf(&ds, "%.2f", conn->request->version);
        result = ds.string;
        break;

    case CLocationIdx:
        Ns_ConnLocationAppend(conn, &ds);
        result = ds.string;
        break;

    case CDriverIdx:
        result = Ns_ConnDriverName(conn);
        break;
    
    case CServerIdx:
        result = Ns_ConnServer(conn);
        break;

    case CStatusIdx:
        Ns_DStringPrintf(&ds, "%d", Ns_ConnResponseStatus(conn));
        result = ds.string;
        break;

    case CSockIdx:
        Ns_DStringPrintf(&ds, "%d", Ns_ConnSock(conn));
        result = ds.string;
        break;
    
    case CIdIdx:
        Ns_DStringPrintf(&ds, "%" PRIiPTR, Ns_ConnId(conn));
        result = ds.string;
        break;
    
    case CFlagsIdx:
        Ns_DStringPrintf(&ds, "%d", conn->flags);
        result = ds.string;
        break;

    case CStartIdx:
        Ns_DStringPrintf(&ds, "%ld", Ns_ConnStartTime(conn)->sec);
        result = ds.string;
        break;

    case CCloseIdx:
        Ns_ConnClose(conn);
        break;

    }
    dupl = estrdup(result != NULL ? result : "");
    Ns_DStringFree(&ds);
    RETURN_STRING(dupl, 0);
}

PHP_FUNCTION(ns_returnredirect)
{
    char *name;
    int nlen;
    Ns_Conn *conn = Ns_GetConn();

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &name, &nlen) == FAILURE) {
        RETURN_FALSE;
    }

    if (conn != NULL) {
        Ns_ConnReturnRedirect(conn, name);
    }
}

PHP_FUNCTION(ns_returndata)
{
    char *type, *data;
    int tlen, dlen, status;
    Ns_Conn *conn = Ns_GetConn();

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "lss", &status, &type, &tlen, &data, &dlen) == FAILURE) {
        RETURN_FALSE;
    }
    if (conn != NULL) {
        Ns_ConnReturnData(conn, status, data, dlen, type);
    }
}

PHP_FUNCTION(ns_returnfile)
{
    char *type, *file;
    int tlen, flen, status;
    Ns_Conn *conn = Ns_GetConn();

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "lss", &status, &type, &tlen, &file, &flen) == FAILURE) {
        RETURN_FALSE;
    }
    if (conn != NULL) {
        Ns_ConnReturnFile(conn, status, type, file);
    }
}

PHP_FUNCTION(ns_queryexists)
{
    char *name;
    int nlen;
    Ns_Conn *conn = Ns_GetConn();

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &name, &nlen) == FAILURE) {
        RETURN_FALSE;
    }
    if (conn != NULL) {
         Ns_Set *form = Ns_ConnGetQuery(conn);
         
        if (form != NULL) {
            RETURN_LONG(Ns_SetIFind(form, name) > -1);
        }
    }
    RETURN_FALSE;
}

PHP_FUNCTION(ns_queryget)
{
    char *name;
    int nlen;
    Ns_Conn *conn = Ns_GetConn();

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &name, &nlen) == FAILURE) {
        RETURN_FALSE;
    }
    if (conn != NULL) {
        Ns_Set *form = Ns_ConnGetQuery(conn);
        
        if (form != NULL) {
            name = Ns_SetIGet(form, name);
            if (name != NULL) {
                RETURN_STRING(name, 1);
            }
        }
    }
}

PHP_FUNCTION(ns_querygetall)
{
    Ns_Conn *conn = Ns_GetConn();

    if (conn != NULL) {
        Ns_Set *form = Ns_ConnGetQuery(conn);
        
        if (form != NULL) {
            int i;
            
            array_init(return_value);
            for (i = 0; i < form->size; i++) {
                char *key = Ns_SetKey(form, i);
                char *value = Ns_SetValue(form, i);
                add_assoc_string(return_value, key, value, 1);
            }
        }
    }
}

PHP_FUNCTION(nsv_get)
{
    int alen, klen;
    char *aname, *key;
    Ns_DString ds;
    Ns_Conn *conn = Ns_GetConn();

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss", &aname, &alen, &key, &klen) == FAILURE) {
        RETURN_FALSE;
    }
    Ns_DStringInit(&ds);
    if (Ns_VarGet(Ns_ConnServer(conn), aname, key, &ds) == NS_OK) {
        char *value = estrdup(ds.string);
        Ns_DStringFree(&ds);
        RETURN_STRING(value, 0);
    }
    Ns_DStringFree(&ds);
}

PHP_FUNCTION(nsv_set)
{
    char *aname, *key, *value;
    int alen, klen, vlen;
    Ns_Conn *conn = Ns_GetConn();

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sss", &aname, &alen, &key, &klen, &value, &vlen) == FAILURE) {
        RETURN_FALSE;
    }
    RETURN_LONG(Ns_VarSet(Ns_ConnServer(conn), aname, key, value, -1));
}

PHP_FUNCTION(nsv_exists)
{
    char *aname, *key;
    int alen, klen;
    Ns_Conn *conn = Ns_GetConn();

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sss", &aname, &alen, &key, &klen) == FAILURE) {
        RETURN_FALSE;
    }
    RETURN_LONG(Ns_VarExists(Ns_ConnServer(conn), aname, key));
}

PHP_FUNCTION(nsv_incr)
{
    char *aname, *key;
    int alen, klen, count = 1;
    Ns_Conn *conn = Ns_GetConn();

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss|l", &aname, &alen, &key, &klen, &count) == FAILURE) {
        RETURN_FALSE;
    }
    RETURN_LONG(Ns_VarIncr(Ns_ConnServer(conn), aname, key, count));
}

PHP_FUNCTION(nsv_unset)
{
    char *aname, *key = NULL;
    int alen, klen;
    Ns_Conn *conn = Ns_GetConn();

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|s", &aname, &alen, &key, &klen) == FAILURE) {
        RETURN_FALSE;
    }
    RETURN_LONG(Ns_VarUnset(Ns_ConnServer(conn), aname, key));
}

PHP_FUNCTION(nsv_append)
{
    char *aname, *key, *value;
    int alen, klen, vlen;
    Ns_Conn *conn = Ns_GetConn();

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sss", &aname, &alen, &key, &klen, &value, &vlen) == FAILURE) {
        RETURN_FALSE;
    }
    RETURN_LONG(Ns_VarAppend(Ns_ConnServer(conn), aname, key, value, -1));
}

/*
 * php_ns_sapi_ub_write() writes data to the client connection.
 */

static int php_ns_sapi_ub_write(const char *str, uint len TSRMLS_DC)
{
    ns_context *ctx = SG(server_context);

    /*
     * We are called from non-connection session, add data to internal buffer 
     */
    if (ctx->conn == NULL) {
        int size = ctx->buffer ? strlen(ctx->buffer) : 0;
        ctx->buffer = ns_realloc(ctx->buffer, size + len + 1);
        strncpy(&(ctx->buffer[size]), str, len);
        ctx->buffer[size + len] = 0;
        return len;
    }

    if (Ns_ConnWriteData(ctx->conn, (void *) str, len, NS_CONN_STREAM) != NS_OK) {
        php_handle_aborted_connection();
        return -1;
    }

    return len;
}

static int php_nsapi_remove_header(sapi_header_struct *sapi_header TSRMLS_DC)
{
        char *header_name, *p;
        ns_context *ctx = SG(server_context);
        
        header_name = ns_strdup(sapi_header->header);

        p = strchr(header_name, ':');
        if (p != NULL) {
            *p = '\0';
        }

        Ns_SetIDeleteKey(Ns_ConnHeaders(ctx->conn), header_name);
        ns_free(header_name);
        
        return ZEND_HASH_APPLY_KEEP;
}


/*
 * php_ns_sapi_header_handler() sets a HTTP reply header to be sent to the client.
 */
static int php_ns_sapi_header_handler(sapi_header_struct *sapi_header,
                                      sapi_header_op_enum op,
                                      sapi_headers_struct *sapi_headers TSRMLS_DC)
{
    int result = 0;
    ns_context *ctx = SG(server_context);
    char *p, *name = NULL;

    /*
     * When there is no connection available, we cannot work on the header
     * fields.
     */
    if (ctx->conn == NULL) {
        Ns_Log(Notice, "nsphp: no connection available; header request ignored");
        return 0;
    }

    /*
     * In the following cases, split the provided header string into tag name
     * and value in order to perform update operations on the header fields.
     * We duplicate the string, but we have to free it (when name != NULL).
     */
   
    switch(op) {
    case SAPI_HEADER_DELETE: 
    case SAPI_HEADER_ADD:
    case SAPI_HEADER_REPLACE:
        name = ns_strdup(sapi_header->header);
        p = strchr(name, ':');
        if (p == NULL) {
            return 0;
        }
        *p++ =  '\0';
        break;

    default:
        break;
    }
    
    switch(op) {
    case SAPI_HEADER_DELETE_ALL:
        zend_llist_apply(&sapi_headers->headers, (llist_apply_func_t) php_nsapi_remove_header TSRMLS_CC);
        break;

    case SAPI_HEADER_DELETE: {
        Ns_SetIDeleteKey(Ns_ConnHeaders(ctx->conn), name);
        break;
    }

    case SAPI_HEADER_ADD:
    case SAPI_HEADER_REPLACE:
        if (strcasecmp(name, "Content-Length") == 0) {
            Ns_ConnSetLengthHeader(ctx->conn, atoll(p), 0);
        } else if (op == SAPI_HEADER_ADD || (strcasecmp(name, "Set-Cookie") == 0)) {
            Ns_ConnSetHeaders(ctx->conn, name, p);
        } else {
            Ns_ConnUpdateHeaders(ctx->conn, name, p);
        }

        result = SAPI_HEADER_ADD;
        break;
        
    default:
        break;
    }

    if (name != NULL) {
        ns_free(name);
    }
    
    return result;
}

/*
 * php_ns_sapi_send_headers() flushes the headers to the client.
 * Called before real content is sent by PHP.
 */

static int php_ns_sapi_send_headers(sapi_headers_struct *sapi_headers TSRMLS_DC)
{
    ns_context *ctx = SG(server_context);

    if (ctx->conn != NULL) {
        Ns_ConnSetResponseStatus(ctx->conn, SG(sapi_headers).http_response_code);
    }

    return SAPI_HEADER_SENT_SUCCESSFULLY;
}

/*
 * php_ns_sapi_read_post() reads a specified number of bytes from
 * the client. Used for POST/PUT requests.
 */

static int php_ns_sapi_read_post(char *buf, uint count_bytes TSRMLS_DC)
{
    const char *data;
    uint max_read;
    ns_context *ctx = SG(server_context);

    if (ctx->conn == NULL || (data = Ns_ConnContent(ctx->conn)) == NULL) {
        return 0;
    }

    max_read = MIN(ctx->data_avail, count_bytes);
    if (max_read > 0) {
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

    if (ctx->conn != NULL) {
        return Ns_SetIGet(ctx->conn->headers, "Cookie");
    }
    return NULL;
}

static void php_ns_sapi_log_message(char *message TSRMLS_DC)
{
    Ns_Log(Error, "nsphp: %s", message);
}

static void php_ns_sapi_info(ZEND_MODULE_INFO_FUNC_ARGS)
{
    char buf[512];
    int i, uptime = Ns_InfoUptime();
    ns_context *ctx = SG(server_context);

    if (ctx->conn == NULL) {
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

static void php_ns_sapi_register_variables(zval *track_vars_array TSRMLS_DC)
{
    int i;
    Ns_DString ds;
    char *p, *value, c;
    ns_context *ctx = SG(server_context);

    if (ctx->conn == NULL) {
        return;
    }

    Ns_DStringInit(&ds);
    for (i = 0; i < Ns_SetSize(ctx->conn->headers); i++) {
        char *key = Ns_SetKey(ctx->conn->headers, i);
        value = Ns_SetValue(ctx->conn->headers, i);

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

    ADD_STRING("REQUEST_METHOD", (char *)ctx->conn->request->method);

    if (Ns_ConnHost(ctx->conn)) {
        Ns_DStringSetLength(&ds, 0);
        value = Ns_ConnLocationAppend(ctx->conn, &ds);
        /*
         * Strip protocol and port from the name
         */
        if ((p = strstr(value, "://"))) {
            value = p + 3;
            if ((p = strchr(value, ':'))) {
                *p = 0;
            }
        }
        ADD_STRING("SERVER_NAME", value);
    }
    if (ctx->conn->request->query) {
        ADD_STRING("QUERY_STRING", ctx->conn->request->query);
    }

    ADD_STRING("SERVER_BUILDDATE", (char *)Ns_InfoBuildDate());

    ADD_STRING("REMOTE_ADDR", (char *)Ns_ConnPeer(ctx->conn));

    Ns_DStringSetLength(&ds, 0);
    Ns_DStringPrintf(&ds, "%lu", Ns_InfoBootTime());
    ADD_STRING("SERVER_BOOTTIME", ds.string);

    Ns_DStringSetLength(&ds, 0);
    Ns_DStringPrintf(&ds, "%d", Ns_ConnPeerPort(ctx->conn));
    ADD_STRING("REMOTE_PORT", ds.string);

    Ns_DStringSetLength(&ds, 0);
    Ns_DStringPrintf(&ds, "%d", Ns_ConnPort(ctx->conn));
    ADD_STRING("SERVER_PORT", ds.string);

    Ns_DStringSetLength(&ds, 0);
    Ns_DStringPrintf(&ds, "%" PRIuz, Ns_ConnContentLength(ctx->conn));
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
    ADD_STRING("DOCUMENT_ROOT", Ns_PagePath(&ds, Ns_ConnServer(ctx->conn), (char *)0));

    Ns_DStringFree(&ds);
}

static int php_ns_sapi_startup(sapi_module_struct * sapi_module)
{
    if (php_module_startup(sapi_module, &php_naviserver_module, 1) == FAILURE) {
        return FAILURE;
    } else {
        return SUCCESS;
    }
}

/*
 * The php_ns_request_handler() is called per request and handles everything for one request.
 */

static int php_ns_sapi_request_handler(void *context, Ns_Conn * conn)
{
    Ns_DString ds;
    ns_context ctx;
    zend_file_handle file_handle = {0};

    TSRMLS_FETCH();

    Ns_DStringInit(&ds);
    Ns_UrlToFile(&ds, Ns_ConnServer(conn), conn->request->url);
    SG(request_info).path_translated = ds.string;

    SG(request_info).query_string = conn->request->query;
    SG(request_info).request_uri = (char *)conn->request->url;
    SG(request_info).request_method = conn->request->method;
    SG(request_info).proto_num = conn->request->version > 1.0 ? 1001 : 1000;
    SG(request_info).content_length = Ns_ConnContentLength(conn);
    SG(request_info).content_type = Ns_SetIGet(conn->headers, "Content-Type");
    SG(request_info).auth_user = STRDUP(Ns_ConnAuthUser(conn));
    SG(request_info).auth_password = STRDUP(Ns_ConnAuthPasswd(conn));
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
        php_execute_script(&file_handle TSRMLS_CC) ? NS_OK : NS_ERROR;
        php_request_shutdown(NULL);
    } zend_catch {
        Ns_Log(Error, "nsphp: error in processing %s", file_handle.filename);;
    } zend_end_try();

    if (!(conn->flags & NS_CONN_SENTHDRS)) {
        Ns_ConnWriteData(conn, NULL, 0, 0);
    }

    Ns_DStringFree(&ds);
    return NS_OK;
}

static int pdo_naviserver_stmt_dtor(pdo_stmt_t *stmt TSRMLS_DC)
{
    ns_pdo_handle *db = (ns_pdo_handle *)stmt->driver_data;

    Ns_DbFlush(db->db);
    Ns_SetTrunc(db->row, 0);
    Ns_SetTrunc(db->db->row, 0);
    Ns_DbSetException(db->db, "", "");
    ns_free(db->sql);
    db->sql = NULL;

    return 1;
}

static int pdo_naviserver_stmt_execute(pdo_stmt_t *stmt TSRMLS_DC)
{
    ns_pdo_handle *db = (ns_pdo_handle *)stmt->driver_data;

    switch (Ns_DbExec(db->db, db->sql)) {
    case NS_ERROR:
        zend_throw_exception_ex(php_pdo_get_exception(), 0 TSRMLS_CC, db->db->dsExceptionMsg.string);
        return 0;

    case NS_DML:
        return 0;

    case NS_ROWS:
        Ns_DbBindRow(db->db);
        stmt->column_count = db->db->row->size;
        break;
    }
    return 1;
}

static int pdo_naviserver_stmt_fetch(pdo_stmt_t *stmt, enum pdo_fetch_orientation ori, long offset TSRMLS_DC)
{
    ns_pdo_handle *db = (ns_pdo_handle *)stmt->driver_data;

    switch (Ns_DbGetRow(db->db, db->row)) {
    case NS_ERROR:
    case NS_END_DATA:
        return 0;
    }
    return 1;
}

static int pdo_naviserver_stmt_describe(pdo_stmt_t *stmt, int colno TSRMLS_DC)
{
    ns_pdo_handle *db = (ns_pdo_handle *)stmt->driver_data;
    struct pdo_column_data *cols = stmt->columns;

    if (colno >= db->db->row->size) {
        return 0;
    }
    cols[colno].param_type = PDO_PARAM_STR;
    cols[colno].name = estrdup(db->db->row->fields[colno].name);
    cols[colno].namelen = strlen(cols[colno].name);
    /* 
     * We do not know column maxwidth, let's use size of the column value
     */
    cols[colno].maxlen = db->db->row->fields[colno].value ? strlen(db->db->row->fields[colno].value) : 0;
    cols[colno].precision = 0;

    return 1;
}

static int pdo_naviserver_stmt_get_col(pdo_stmt_t *stmt, int colno, char **ptr, unsigned long *len, int *caller_frees TSRMLS_DC)
{
    ns_pdo_handle *db = (ns_pdo_handle *)stmt->driver_data;

    if (colno >= db->row->size) {
        return 0;
    }
    *ptr = db->row->fields[colno].value;
    *len = *ptr ? strlen(db->row->fields[colno].value) : 0;
    return 1;
}

static int pdo_naviserver_handle_fetch_error(pdo_dbh_t *dbh, pdo_stmt_t *stmt, zval *info TSRMLS_DC)
{
    ns_pdo_handle *db = (ns_pdo_handle *)dbh->driver_data;

    add_next_index_string(info, db->db->dsExceptionMsg.string, 0);
    return 1;
}

static int pdo_naviserver_handle_closer(pdo_dbh_t *dbh TSRMLS_DC)
{
    ns_pdo_handle *db = (ns_pdo_handle *)dbh->driver_data;

    if (db) {
        ns_free(db->sql);
        Ns_SetFree(db->row);
        Ns_DbPoolPutHandle(db->db);
        ns_free(db);
        dbh->driver_data = NULL;
        return 1;
    }
    return 0;
}

static int pdo_naviserver_handle_quoter(pdo_dbh_t *dbh, const char *unquoted, int unquotedlen, char **quoted, int *quotedlen, enum pdo_param_type paramtype TSRMLS_DC)
{
    char *q;
    int l = 1;

    *quoted = q = safe_emalloc(2, unquotedlen, 3);
    *q++ = '\'';

    while (unquotedlen--) {
        if (*unquoted == '\'') {
            *q++ = '\'';
            *q++ = '\'';
            l += 2;
        } else {
            *q++ = *unquoted;
            ++l;
        }
        unquoted++;
    }

    *q++ = '\'';
    *q++ = '\0';
    *quotedlen = l+1;
    return 1;
}

static int pdo_naviserver_handle_preparer(pdo_dbh_t *dbh, const char *sql, long sql_len, pdo_stmt_t *stmt, zval *driver_options TSRMLS_DC)
{
    ns_pdo_handle *db = (ns_pdo_handle *)dbh->driver_data;

    ns_free(db->sql);
    db->sql = ns_strcopy(sql);
    stmt->driver_data = db;
    stmt->methods = &pdo_naviserver_stmt_methods;
    stmt->supports_placeholders = PDO_PLACEHOLDER_NONE;

    return 1;
}

static long pdo_naviserver_handle_doer(pdo_dbh_t *dbh, const char *sql, long sql_len TSRMLS_DC)
{
    ns_pdo_handle *db = (ns_pdo_handle *)dbh->driver_data;

    switch (Ns_DbExec(db->db, (char*)sql)) {
    case NS_ERROR:
        return -1;

    case NS_DML:
        return 0;

    default:
        return 1;
    }
}

static int pdo_naviserver_handle_factory(pdo_dbh_t *dbh, zval *driver_options TSRMLS_DC)
{
    ns_pdo_handle *db = ns_malloc(sizeof(ns_pdo_handle));

    db->db = Ns_DbPoolTimedGetHandle((char *)dbh->data_source, NULL);
    if (db->db == NULL) {
        ns_free(db);
        zend_throw_exception_ex(php_pdo_get_exception(), 0 TSRMLS_CC, "Unable to get handle for %s", dbh->data_source);
        return -1;
    }
    db->sql = NULL;
    db->row = Ns_SetCreate(NULL);
    dbh->max_escaped_char_length = 2;
    dbh->alloc_own_columns = 1;
    dbh->methods = &pdo_naviserver_methods;
    dbh->driver_data = db;

    return 1;
}

/*
 * Local Variables:
 * mode: c
 * c-basic-offset: 4
 * fill-column: 78
 * indent-tabs-mode: nil
 * End:
 */
