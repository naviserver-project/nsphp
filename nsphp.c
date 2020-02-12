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
 *  PHP module for NaviServer
 *
 *  Author: Vlad Seryakov <vlad@crystalballinc.com>
 *          Gustaf Neumann (Port to PHP 7)
 *          based on AOLserver module by Sascha Schumann <sascha@schumann.cx>
 */

#include "ns.h"
#include "nsdb.h"

#define NSPHP_VERSION "0.3"
/*
 * Undefine the following macros defined by ns.h, which are as well defined by
 * php_config.h
 */
#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION

#define ZEND_ENABLE_STATIC_TSRMLS_CACHE 1

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
# error NaviServer module nsphp is only usable in thread-safe mode
#endif

#if (PHP_MAJOR_VERSION < 7)
# error NaviServer module nsphp requires at least PHP 7
#endif

#define ADD_STRING(name,buf)  php_register_variable(name, buf, track_vars_array TSRMLS_CC)
#define STRDUP(s)             (s != NULL ? estrdup(s) : NULL)

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


PHP_FUNCTION(ns_conn);
PHP_FUNCTION(ns_eval);
PHP_FUNCTION(ns_header);
PHP_FUNCTION(ns_headers);
PHP_FUNCTION(ns_info);
PHP_FUNCTION(ns_log);
PHP_FUNCTION(ns_outputheaders);
PHP_FUNCTION(ns_queryexists);
PHP_FUNCTION(ns_queryget);
PHP_FUNCTION(ns_querygetall);
PHP_FUNCTION(ns_returndata);
PHP_FUNCTION(ns_returnfile);
PHP_FUNCTION(ns_returnredirect);
PHP_FUNCTION(nsv_append);
PHP_FUNCTION(nsv_exists);
PHP_FUNCTION(nsv_get);
PHP_FUNCTION(nsv_incr);
PHP_FUNCTION(nsv_set);
PHP_FUNCTION(nsv_unset);

PHP_MINIT_FUNCTION(pdo_naviserver);
PHP_MSHUTDOWN_FUNCTION(pdo_naviserver);
PHP_MINFO_FUNCTION(pdo_naviserver);
PHP_RSHUTDOWN_FUNCTION(pdo_naviserver);

static Tcl_ObjCmdProc php_ns_tcl_cmd;
static Ns_TclTraceProc php_ns_tcl_init;

static Ns_ThreadArgProc ThreadArgProc;

static int pdo_naviserver_handle_factory(pdo_dbh_t *dbh, zval *driver_options);
static int pdo_naviserver_handle_fetch_error(pdo_dbh_t *dbh, pdo_stmt_t *stmt, zval *info);
static int pdo_naviserver_handle_closer(pdo_dbh_t *dbh);

static int pdo_naviserver_stmt_dtor(pdo_stmt_t *stmt);
static int pdo_naviserver_stmt_execute(pdo_stmt_t *stmt);
static int pdo_naviserver_stmt_fetch(pdo_stmt_t *stmt, enum pdo_fetch_orientation ori, long offset);
static int pdo_naviserver_stmt_describe(pdo_stmt_t *stmt, int colno);
static int pdo_naviserver_stmt_get_col(pdo_stmt_t *stmt, int colno, char **ptr, unsigned long *len, int *caller_frees);

static size_t php_ns_sapi_ub_write(const char *str, size_t len);
static size_t php_ns_sapi_read_post(char *buf, size_t count_bytes);
static void php_ns_sapi_log_message(char *message, int syslog_type_int);

static int pdo_naviserver_handle_preparer(pdo_dbh_t *dbh, const char *sql, size_t sql_len, pdo_stmt_t *stmt, zval *driver_options);
static zend_long pdo_naviserver_handle_doer(pdo_dbh_t *dbh, const char *sql, size_t sql_len);
static int pdo_naviserver_handle_quoter(pdo_dbh_t *dbh, const char *unquoted, size_t unquotedlen, char **quoted, size_t *quotedlen, enum pdo_param_type paramtype);


static int php_ns_sapi_header_handler(sapi_header_struct *sapi_header,
                                      sapi_header_op_enum op,
                                      sapi_headers_struct *sapi_headers);

static int php_ns_sapi_send_headers(sapi_headers_struct *sapi_headers);
static char *php_ns_sapi_read_cookies(TSRMLS_D);
static void php_ns_sapi_register_variables(zval *track_vars_array);

static void php_ns_sapi_info(ZEND_MODULE_INFO_FUNC_ARGS);
static int php_ns_sapi_startup(sapi_module_struct * sapi_module);

static Ns_OpProc php_ns_sapi_request_handler;

/*
 * defined in /usr/local/src/php-5.6.6//main/SAPI.h
 */
static sapi_module_struct naviserver_sapi_module = {
    "naviserver",
    "NaviServer",

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
    NULL,                                     /* terminate_process */
    STANDARD_SAPI_MODULE_PROPERTIES
};


static zend_function_entry naviserver_functions[] = {
    PHP_FE(ns_conn,          NULL)
    PHP_FE(ns_eval,          NULL)
    PHP_FE(ns_header,        NULL)
    PHP_FE(ns_headers,       NULL)
    PHP_FE(ns_info,          NULL)
    PHP_FE(ns_log,           NULL)
    PHP_FE(ns_outputheaders, NULL)
    PHP_FE(ns_queryexists,   NULL)
    PHP_FE(ns_queryget,      NULL)
    PHP_FE(ns_querygetall,   NULL)
    PHP_FE(ns_returndata,    NULL)
    PHP_FE(ns_returnfile,    NULL)
    PHP_FE(ns_returnredirect,NULL)
    PHP_FE(nsv_append,       NULL)
    PHP_FE(nsv_exists,       NULL)
    PHP_FE(nsv_get,          NULL)
    PHP_FE(nsv_incr,         NULL)
    PHP_FE(nsv_set,          NULL)
    PHP_FE(nsv_unset,        NULL)
    {NULL, NULL, NULL, 0, 0}
};

static zend_module_entry nsphp_module_entry = {
    STANDARD_MODULE_HEADER,
    "Naviserver",
    naviserver_functions,
    NULL,
    NULL,
    NULL,
    NULL,
    php_ns_sapi_info,
    NSPHP_VERSION,
    STANDARD_MODULE_PROPERTIES
};

ZEND_TSRMLS_CACHE_DEFINE()
ZEND_GET_MODULE(nsphp)

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
    NULL,                               /* get_driver_methods */
    NULL,                               /* persistent_shutdown */
    NULL                                /* in_transaction */
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



NS_EXPORT int Ns_ModuleVersion = 1;
NS_EXPORT Ns_ModuleInitProc Ns_ModuleInit;

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

int Ns_ModuleInit(const char *server, const char *module)
{
    size_t      i;
    const char *path;
    Ns_Set     *set;

    ZEND_TSRMLS_CACHE_UPDATE();

    tsrm_startup(1, 1, TSRM_ERROR_LEVEL_INFO, NULL);
    zend_signal_startup();

    sapi_startup(&naviserver_sapi_module);
    if (sapi_module.startup(&naviserver_sapi_module) == FAILURE) {
        Ns_Log(Error, "Error during initialization of nsphp");
    }

    php_pdo_register_driver(&pdo_naviserver_driver);

    /*
     * read the configuration
     */
    path = Ns_ConfigGetPath(server, module, (char *)0);
    set = Ns_ConfigGetSection(path);

    for (i = 0; set && i < Ns_SetSize(set); i++) {
        const char *key = Ns_SetKey(set, i);
        const char *value = Ns_SetValue(set, i);

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

    Ns_Log(Notice, "nsphp: started version %s with PHP %s", NSPHP_VERSION, PHP_VERSION);
    return NS_OK;
}


/*
 *----------------------------------------------------------------------
 *
 * ZvalToObj --
 *
 *      Convert PHP zval to Tcl_Obj
 *
 * Results:
 *      Fresh Tcl_Obj
 *
 * Side effects:
 *      memory allocation
 *
 *----------------------------------------------------------------------
 */

static Tcl_Obj*
ZvalToObj(zval *zvPtr) {
    Tcl_Obj *result = TCL_OK;

    /* fprintf(stderr, "zval type %d\n", Z_TYPE_P(zvPtr));*/
    if (Z_TYPE_P(zvPtr) == IS_LONG) {
        result = Tcl_NewLongObj(zval_get_long(zvPtr));
    } else if (Z_TYPE_P(zvPtr) == IS_STRING) {
        Tcl_NewStringObj(Z_STRVAL(*zvPtr), (int)Z_STRLEN(*zvPtr));
    } else {
        /*fprintf(stderr, "zval convert to string\n");*/
        convert_to_string(zvPtr);
        Tcl_NewStringObj(Z_STRVAL(*zvPtr), (int)Z_STRLEN(*zvPtr));
    }
    return result;
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

static int php_ns_tcl_cmd(ClientData UNUSED(clientdata), Tcl_Interp *interp, int objc, Tcl_Obj *const objv[])
{
    zval             val;
    int              status, cmd;
    ns_context       ctx;
    zend_file_handle file_handle;

    enum {
#if 0
        cmdCALL,
#endif
        cmdEVAL, cmdEVALFILE, cmdVAR, cmdVERSION
    };
    static const char *subcmd[] = {
#if 0
        "call",
#endif
        "eval", "evalfile", "var", "version",
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
                int r = zend_eval_string(Tcl_GetString(objv[2]), &val, (char*)"ns:php" TSRMLS_CC);
                if (r == SUCCESS) {
                    Tcl_SetObjResult(interp, ZvalToObj(&val));
                } else {
                    Tcl_SetObjResult(interp, Tcl_NewStringObj("php fails", -1));
                    status = TCL_ERROR;
                }
                zval_ptr_dtor(&val);
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
            int r = php_execute_script(&file_handle TSRMLS_CC);
            if (r != SUCCESS) {
                Tcl_SetObjResult(interp, Tcl_NewStringObj("php fails", -1));
                status = TCL_ERROR;
            }
            zend_try {
                php_request_shutdown(NULL);
            } zend_end_try();
        }
        break;

#if 0
    case cmdCALL: {
        /*
         * Can be easily handled via "eval", it seems that argument passing
         * was never implemented.... but it can be added with modest effort
         * when needed.
         */
        zval name;
        if (objc < 3) {
            Tcl_WrongNumArgs(interp, 2, objv, "functionname ...");
            status = TCL_ERROR;
            break;
        }
        zend_try {
            if (php_request_startup(TSRMLS_C) != FAILURE) {
                ZVAL_STRING(&name, Tcl_GetString(objv[2]));

                int r = call_user_function(CG(function_table), &val, &name, NULL, 0, NULL);
                if (r == SUCCESS) {
                    Tcl_SetObjResult(interp, ZvalToObj(&val));
                } else {
                    Tcl_SetObjResult(interp, Tcl_NewStringObj("php fails", -1));
                    status = TCL_ERROR;
                }
                zval_ptr_dtor(&name);
                php_request_shutdown(NULL);
            }
        } zend_end_try();
        break;
    }
#endif

    case cmdVAR:
        if (objc < 3) {
            Tcl_WrongNumArgs(interp, 2, objv, "varname");
            status = TCL_ERROR;
            break;
        }
        zend_try {
            if (php_request_startup(TSRMLS_C) != FAILURE) {
                int r = zend_eval_string(Tcl_GetString(objv[2]), &val, (char*)"ns:php" TSRMLS_CC);
                if (r == SUCCESS) {
                    Tcl_SetObjResult(interp, ZvalToObj(&val));
                } else {
                    Tcl_SetObjResult(interp, Tcl_NewStringObj("php fails", -1));
                    status = TCL_ERROR;
                }
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
    Ns_GetProcInfo(dsPtr, (ns_funcptr_t)proc, arg);
}

PHP_FUNCTION(ns_headers)
{
    const Ns_Conn *conn = Ns_GetConn();

    if (conn != NULL) {
        Ns_Set *hdrs = Ns_ConnHeaders(conn);

        if (hdrs != NULL) {
            size_t i;

            array_init(return_value);
            for (i = 0; i < Ns_SetSize(hdrs); i++) {
                const char *key   = Ns_SetKey(hdrs, i);
                const char *value = Ns_SetValue(hdrs, i);
                add_assoc_string(return_value, key, value);
            }
        }
    }
}

PHP_FUNCTION(ns_outputheaders)
{
    const Ns_Conn *conn = Ns_GetConn();

    if (conn != NULL) {
        Ns_Set *hdrs = Ns_ConnOutputHeaders(conn);

        if (hdrs != NULL) {
            size_t i;

            array_init(return_value);
            for (i = 0; i < Ns_SetSize(hdrs); i++) {
                const char *key = Ns_SetKey(hdrs, i);
                const char *value = Ns_SetValue(hdrs, i);
                add_assoc_string(return_value, key, value);
            }
        }
    }
}

PHP_FUNCTION(ns_header)
{
    const char    *name;
    size_t         nlen;
    uint32_t       num_args = ZEND_NUM_ARGS();

    if (num_args == 1 && zend_parse_parameters(num_args, "s", &name, &nlen) == SUCCESS) {
        const Ns_Conn *conn = Ns_GetConn();

        if (conn != NULL) {
            const char *result = Ns_SetIGetValue(Ns_ConnHeaders(conn), name, NULL);
            if (result != NULL) {
                RETURN_STRING(result);
            }
        }
    }
    RETURN_FALSE;
}

PHP_FUNCTION(ns_eval)
{
    const char *name;
    size_t      nlen;
    uint32_t    num_args = ZEND_NUM_ARGS();

    if (num_args == 1 && zend_parse_parameters(num_args, "s", &name, &nlen) == SUCCESS) {
        Tcl_Interp *interp = Ns_GetConnInterp(Ns_GetConn());

        if (Tcl_EvalEx(interp, name, (int)nlen, 0) != TCL_OK) {
            (void) Ns_TclLogErrorInfo(interp, "\n(context: php eval)");
            RETURN_FALSE;

        } else {
            const char *string;
            int         length;
            Tcl_Obj    *resultObj = Tcl_GetObjResult(interp);

            string = Tcl_GetStringFromObj(resultObj, &length);
            RETVAL_STRINGL(string, (size_t)length);
        }
    } else {
        RETURN_FALSE;
    }
}

PHP_FUNCTION(ns_log)
{
    const char *level, *str;
    size_t      llen, slen;
    uint32_t    num_args = ZEND_NUM_ARGS();

    if (num_args == 2 && zend_parse_parameters(num_args, "ss", &level, &llen, &str, &slen) == SUCCESS) {
        int severity = !strcasecmp(level, "Error") ? Error :
            !strcasecmp(level, "Warning") ? Warning :
            !strcasecmp(level, "Debug") ? Debug :
            !strcasecmp(level, "Fatal") ? Fatal : Notice;

        Ns_Log(severity, "%s", str);
    } else {
        RETURN_FALSE;
    }
}

PHP_FUNCTION(ns_info)
{
    const char *name;
    uint32_t    num_args = ZEND_NUM_ARGS();
    size_t      nlen;
    Ns_DString  ds;

    static const char *cmds[] = {
        "address", "boottime", "builddate", "threads",
        "config", "home", "hostname", "locks", "log",
        "major", "minor", "name", "pageroot", "patchlevel",
        "pid", "platform", "tag", "uptime", "version", NULL };
    enum {
        IAddressIdx, IBoottimeIdx, IBuilddateIdx, IThreadsIdx,
        IConfigIdx, IHomeIdx, hostINameIdx, ILocksIdx, ILogIdx,
        IMajorIdx, IMinorIdx, INameIdx, IPageRootIdx, IPatchLevelIdx,
        IPidIdx, IPlatformIdx, ITagIdx, IUptimeIdx, IVersionIdx, INoneIdx
    } opt;

    if (num_args != 1 || zend_parse_parameters(num_args, "s", &name, &nlen) == FAILURE) {
        RETURN_FALSE;
    }

    for (opt = 0; cmds[opt] != NULL; opt++) {
        //Ns_Log(Notice, "ns_info opt %d cmd '%s' name '%s'", opt, cmds[opt], name);
        if (!strcmp(cmds[opt], name)) {
            break;
        }
    }

    if (opt == INoneIdx ) {
        RETURN_FALSE;
    }

    Ns_DStringInit(&ds);

    switch(opt) {
    case IAddressIdx:
        Tcl_DStringAppend(&ds, Ns_InfoAddress(), -1);
        break;

    case IBoottimeIdx:
        Ns_DStringPrintf(&ds, "%lu", Ns_InfoBootTime());
        break;

    case IBuilddateIdx:
        Tcl_DStringAppend(&ds, Ns_InfoBuildDate(), -1);
        break;

    case IConfigIdx:
        Tcl_DStringAppend(&ds, Ns_InfoConfigFile(), -1);
        break;

    case IHomeIdx:
        Tcl_DStringAppend(&ds, Ns_InfoHomePath(), -1);
        break;

    case hostINameIdx:
        Tcl_DStringAppend(&ds, Ns_InfoHostname(), -1);
        break;

    case ILogIdx:
        Tcl_DStringAppend(&ds, Ns_InfoErrorLog(), -1);
        break;

    case IMajorIdx:
        Ns_DStringPrintf(&ds, "%d", NS_MAJOR_VERSION);
        break;

    case IMinorIdx:
        Ns_DStringPrintf(&ds, "%d", NS_MINOR_VERSION);
        break;

    case INameIdx:
        Tcl_DStringAppend(&ds, Ns_InfoServerName(), -1);
        break;

    case IPageRootIdx:
        Ns_PagePath(&ds, "", (char *)0);
        break;

    case IPatchLevelIdx:
        Tcl_DStringAppend(&ds, NS_PATCH_LEVEL, -1);
        break;

    case IPidIdx:
        Ns_DStringPrintf(&ds, "%d", Ns_InfoPid());
        break;

    case IPlatformIdx:
        Tcl_DStringAppend(&ds, Ns_InfoPlatform(), -1);
        break;

    case ILocksIdx:
        Ns_MutexList(&ds);
        break;

    case ITagIdx:
        Tcl_DStringAppend(&ds, Ns_InfoTag(), -1);
        break;

    case IThreadsIdx:
        Ns_ThreadList(&ds, ThreadArgProc);
        break;

    case IUptimeIdx:
        Ns_DStringPrintf(&ds, "%ld", Ns_InfoUptime());
        break;

    case IVersionIdx:
        Tcl_DStringAppend(&ds, NS_VERSION, -1);
        break;

    case INoneIdx:
        break;
    }

    RETVAL_STRINGL(ds.string, (size_t)ds.length);
    Ns_DStringFree(&ds);
}

PHP_FUNCTION(ns_conn)
{
    Ns_Conn     *conn;
    Tcl_DString  ds;
    const char  *name;
    size_t       nlen;
    int          result = TCL_OK;
    uint32_t     num_args = ZEND_NUM_ARGS();

    static const char *cmds[] = {
        "authpassword", "authuser", "close", "content", "contentlength",
        "driver", "encoding", "flags",
        "host", "id", "isconnected", "location", "method",
        "peeraddr", "peerport", "port", "protocol", "query", "request",
        "server", "sock", "start", "status", "url", "urlc", "urlencoding",
        "urlv", "version",
        NULL
    };
    enum ISubCmdIdx {
        CAuthPasswordIdx, CAuthUserIdx, CCloseIdx, CContentIdx, CContentLengthIdx,
        CDriverIdx, CEncodingIdx, CFlagsIdx,
        CHostIdx, CIdIdx, CIsConnectedIdx, CLocationIdx, CMethodIdx,
        CPeerAddrIdx, CPeerPortIdx, CPortIdx, CProtocolIdx, CQueryIdx, CRequestIdx,
        CServerIdx, CSockIdx, CStartIdx, CStatusIdx, CUrlIdx, CUrlcIdx, CUrlEncodingIdx,
        CUrlvIdx, CVersionIdx
    } opt;

    if (num_args != 1 || zend_parse_parameters(num_args, "s", &name, &nlen) == FAILURE) {
        RETURN_FALSE;
    }

    for (opt = 0; cmds[opt]; opt++) {
        if (!strcmp(cmds[opt], name)) {
            break;
        }
    }

    conn = Ns_GetConn();

    if ((opt != CIsConnectedIdx) && (conn == NULL)) {
        RETURN_FALSE;
    }

    Tcl_DStringInit(&ds);
    switch(opt) {
    case CIsConnectedIdx:
        Tcl_DStringAppend(&ds, conn ? "true" : "false", -1);
        break;

    case CUrlvIdx:
        Ns_DStringPrintf(&ds, "%s ",conn->request.urlv);
        break;

    case CAuthUserIdx:
        Tcl_DStringAppend(&ds, Ns_ConnAuthUser(conn), -1);
        break;

    case CAuthPasswordIdx:
        Tcl_DStringAppend(&ds, Ns_ConnAuthPasswd(conn), -1);
        break;

    case CContentIdx:
        Tcl_DStringAppend(&ds, Ns_ConnContent(conn), -1);
        break;

    case CContentLengthIdx:
        Ns_DStringPrintf(&ds,"%" PRIuz,conn->contentLength);
        break;

    case CEncodingIdx:
        Tcl_DStringAppend(&ds, Tcl_GetEncodingName(Ns_ConnGetEncoding(conn)), -1);
        break;

    case CUrlEncodingIdx:
        Tcl_DStringAppend(&ds, Tcl_GetEncodingName(Ns_ConnGetUrlEncoding(conn)), -1);
        break;

    case CPeerAddrIdx:
        Tcl_DStringAppend(&ds, Ns_ConnPeerAddr(conn), -1);
        break;

    case CPeerPortIdx:
        Ns_DStringPrintf(&ds, "%d", Ns_ConnPeerPort(conn));
        break;

    case CRequestIdx:
        Tcl_DStringAppend(&ds, conn->request.line, -1);
        break;

    case CMethodIdx:
        Tcl_DStringAppend(&ds, conn->request.method, -1);
        break;

    case CProtocolIdx:
        Tcl_DStringAppend(&ds, conn->request.protocol, -1);
        break;

    case CHostIdx:
        Tcl_DStringAppend(&ds, Ns_ConnHost(conn), -1);
        break;

    case CPortIdx:
        Ns_DStringPrintf(&ds, "%hu", Ns_ConnPort(conn));
        break;

    case CUrlIdx:
        Tcl_DStringAppend(&ds, conn->request.url, -1);
        break;

    case CQueryIdx:
        Tcl_DStringAppend(&ds, conn->request.query, -1);
        break;

    case CUrlcIdx:

        Ns_DStringPrintf(&ds, "%d", conn->request.urlc);
        break;

    case CVersionIdx:
        Ns_DStringPrintf(&ds, "%.2f", conn->request.version);
        break;

    case CLocationIdx:
        Ns_ConnLocationAppend(conn, &ds);
        break;

    case CDriverIdx:
        Tcl_DStringAppend(&ds, Ns_ConnDriverName(conn), -1);
        break;

    case CServerIdx:
        Tcl_DStringAppend(&ds, Ns_ConnServer(conn), -1);
        break;

    case CStatusIdx:
        Ns_DStringPrintf(&ds, "%d", Ns_ConnResponseStatus(conn));
        break;

    case CSockIdx:
        Ns_DStringPrintf(&ds, "%d", Ns_ConnSock(conn));
        break;

    case CIdIdx:
        Ns_DStringPrintf(&ds, "%" PRIiPTR, Ns_ConnId(conn));
        break;

    case CFlagsIdx:
        Ns_DStringPrintf(&ds, "%d", conn->flags);
        break;

    case CStartIdx:
        Ns_DStringPrintf(&ds, "%ld", Ns_ConnStartTime(conn)->sec);
        break;

    case CCloseIdx:
        Ns_ConnClose(conn);
        break;
    }

    if (result == TCL_OK) {
        RETVAL_STRINGL(ds.string, (size_t)ds.length);
    }
    Ns_DStringFree(&ds);
}

PHP_FUNCTION(ns_returnredirect)
{
    const char *name;
    size_t      nlen;
    uint32_t    num_args = ZEND_NUM_ARGS();

    if (num_args != 1 || zend_parse_parameters(num_args, "s", &name, &nlen) == FAILURE) {
        RETURN_FALSE;
    } else {
        Ns_Conn *conn = Ns_GetConn();
        if (conn != NULL) {
            Ns_ConnReturnRedirect(conn, name);
        } else {
            RETURN_FALSE;
        }
    }
}

PHP_FUNCTION(ns_returndata)
{
    const char *type, *data;
    size_t      tlen, dlen;
    zend_long   status;
    uint32_t    num_args = ZEND_NUM_ARGS();

    if (num_args != 3 || zend_parse_parameters(num_args, "lss", &status, &type, &tlen, &data, &dlen) == FAILURE) {
        RETURN_FALSE;

    } else {
        Ns_Conn *conn = Ns_GetConn();

        if (conn != NULL) {
            Ns_ConnReturnData(conn, (int)status, data, (ssize_t)dlen, type);
        } else {
            RETURN_FALSE;
        }
    }
}

PHP_FUNCTION(ns_returnfile)
{
    const char *type, *file;
    size_t      tlen, flen;
    zend_long   status;
    uint32_t    num_args = ZEND_NUM_ARGS();

    if (num_args != 3 || zend_parse_parameters(num_args, "lss", &status, &type, &tlen, &file, &flen) == FAILURE) {
        RETURN_FALSE;

    } else {
        Ns_Conn *conn = Ns_GetConn();

        if (conn != NULL) {
            Ns_ConnReturnFile(conn, (int)status, type, file);
        } else {
            RETURN_FALSE;
        }
    }
}

PHP_FUNCTION(ns_queryexists)
{
    const char *name;
    size_t      nlen;
    uint32_t    num_args = ZEND_NUM_ARGS();

    if (num_args == 1 && zend_parse_parameters(num_args, "s", &name, &nlen) == SUCCESS) {
        Ns_Conn  *conn = Ns_GetConn();

        if (conn != NULL) {
            Ns_Set *form = Ns_ConnGetQuery(conn);

            if (form != NULL) {
                RETURN_LONG(Ns_SetIFind(form, name) > -1);
            }
        }
    }
    RETURN_FALSE;
}

PHP_FUNCTION(ns_queryget)
{
    const char *name;
    size_t      nlen;
    uint32_t    num_args = ZEND_NUM_ARGS();

    if (num_args == 1 && (zend_parse_parameters(num_args, "s", &name, &nlen) == SUCCESS)) {
        Ns_Conn  *conn = Ns_GetConn();

        if (conn != NULL) {
            Ns_Set *form = Ns_ConnGetQuery(conn);

            if (form != NULL) {
                const char *value = Ns_SetIGet(form, name);
                if (value != NULL) {
                    RETVAL_STRINGL(value, strlen(value));
                    return;
                }
            }
        }
    }
    RETURN_FALSE;
}

PHP_FUNCTION(ns_querygetall)
{
    Ns_Conn *conn = Ns_GetConn();

    if (conn != NULL) {
        Ns_Set *form = Ns_ConnGetQuery(conn);

        if (form != NULL) {
            size_t i;

            array_init(return_value);
            for (i = 0; i < form->size; i++) {
                const char *key = Ns_SetKey(form, i);
                const char *value = Ns_SetValue(form, i);
                add_assoc_string(return_value, key, value);
            }
        }
    }
    RETURN_FALSE;
 }

PHP_FUNCTION(nsv_get)
{
    uint32_t    num_args = ZEND_NUM_ARGS();
    size_t      alen, klen;
    const char *aname, *key;

    if (num_args != 2 || zend_parse_parameters(num_args, "ss", &aname, &alen, &key, &klen) == FAILURE) {
        RETURN_FALSE;
    } else {
        Ns_DString     ds;
        const Ns_Conn *conn = Ns_GetConn();

        Ns_DStringInit(&ds);
        if (Ns_VarGet(Ns_ConnServer(conn), aname, key, &ds) == NS_OK) {
            RETVAL_STRINGL(ds.string, (size_t)ds.length);
        } else {
            RETURN_FALSE;
        }
        Ns_DStringFree(&ds);
    }
}

PHP_FUNCTION(nsv_set)
{
    const char *aname, *key, *value;
    size_t      alen, klen, vlen;
    uint32_t    num_args = ZEND_NUM_ARGS();

    if (num_args != 3 || zend_parse_parameters(num_args, "sss", &aname, &alen, &key, &klen, &value, &vlen) == FAILURE) {
        RETURN_FALSE;

    } else {
        const Ns_Conn *conn = Ns_GetConn();

        RETURN_LONG(Ns_VarSet(Ns_ConnServer(conn), aname, key, value, -1));
    }
}

PHP_FUNCTION(nsv_exists)
{
    const char *aname, *key;
    size_t      alen, klen;
    uint32_t    num_args = ZEND_NUM_ARGS();

    if (num_args != 3 || zend_parse_parameters(num_args, "sss", &aname, &alen, &key, &klen) == FAILURE) {
        RETURN_FALSE;

    } else {
        const Ns_Conn *conn = Ns_GetConn();

        RETURN_LONG(Ns_VarExists(Ns_ConnServer(conn), aname, key));
    }
}

PHP_FUNCTION(nsv_incr)
{
    const char *aname, *key;
    size_t      alen, klen;
    zend_long   count = 1;
    uint32_t    num_args = ZEND_NUM_ARGS();

    if (num_args < 2 || num_args > 3
        || zend_parse_parameters(num_args, "ss|l", &aname, &alen, &key, &klen, &count) == FAILURE) {
        RETURN_FALSE;

    } else {
        const Ns_Conn *conn = Ns_GetConn();

        RETURN_LONG(Ns_VarIncr(Ns_ConnServer(conn), aname, key, (int)count));
    }
}

PHP_FUNCTION(nsv_unset)
{
    const char *aname, *key = NULL;
    size_t      alen, klen;
    uint32_t    num_args = ZEND_NUM_ARGS();

    if (num_args < 1 || num_args > 2
        || zend_parse_parameters(num_args, "s|s", &aname, &alen, &key, &klen) == FAILURE) {
        RETURN_FALSE;

    } else {
        const Ns_Conn *conn = Ns_GetConn();

        RETURN_LONG(Ns_VarUnset(Ns_ConnServer(conn), aname, key));
    }
}

PHP_FUNCTION(nsv_append)
{
    const char *aname, *key, *value;
    size_t      alen, klen, vlen;
    uint32_t    num_args = ZEND_NUM_ARGS();

    if (num_args != 3 || zend_parse_parameters(num_args, "sss", &aname, &alen, &key, &klen, &value, &vlen) == FAILURE) {
        RETURN_FALSE;

    } else {
        const Ns_Conn *conn = Ns_GetConn();

        RETURN_LONG(Ns_VarAppend(Ns_ConnServer(conn), aname, key, value, -1));
    }
}

/*
 * php_ns_sapi_ub_write() writes data to the client connection.
 */
static size_t php_ns_sapi_ub_write(const char *str, size_t len)
{
    ns_context *ctx = SG(server_context);

    /*
     * We are called from non-connection session, add data to internal buffer
     */
    if (ctx->conn == NULL) {
        size_t size = ctx->buffer ? strlen(ctx->buffer) : 0u;

        ctx->buffer = ns_realloc(ctx->buffer, size + len + 1);
        strncpy(&(ctx->buffer[size]), str, len);
        ctx->buffer[size + len] = 0;
        return len;
    }

    if (Ns_ConnWriteData(ctx->conn, (void *) str, len, NS_CONN_STREAM) != NS_OK) {
        php_handle_aborted_connection();
        return 0;
    }

    return len;
}

static int php_nsapi_remove_header(sapi_header_struct *sapi_header)
{
    char       *header_name, *p;
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
                                      sapi_headers_struct *sapi_headers)
{
    int         result = 0;
    ns_context *ctx = SG(server_context);

    /*
     * When there is no connection available, we cannot work on the header
     * fields.
     */
    if (ctx->conn == NULL) {
        Ns_Log(Notice, "nsphp: no connection available; header request ignored");

    } else {
        char *p = NULL, *name = NULL;

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
            // SAPI_HEADER_DELETE_ALL
            // SAPI_HEADER_SET_STATUS
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
                Ns_ConnSetLengthHeader(ctx->conn, (size_t)atoll(p), 0);
            } else if (op == SAPI_HEADER_ADD || (strcasecmp(name, "Set-Cookie") == 0)) {
                Ns_ConnSetHeaders(ctx->conn, name, p);
            } else {
                Ns_ConnUpdateHeaders(ctx->conn, name, p);
            }

            result = SAPI_HEADER_ADD;
            break;

        default:
            // SAPI_HEADER_SET_STATUS
            break;
        }

        if (name != NULL) {
            ns_free(name);
        }
    }
    return result;
}

/*
 * php_ns_sapi_send_headers() flushes the headers to the client.
 * Called before real content is sent by PHP.
 */

static int php_ns_sapi_send_headers(sapi_headers_struct *sapi_headers)
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

static size_t php_ns_sapi_read_post(char *buf, size_t count_bytes)
{
    const char *data;
    size_t      max_read;
    ns_context *ctx = SG(server_context);

    if (ctx->conn == NULL || (data = Ns_ConnContent(ctx->conn)) == NULL) {
        max_read = 0u;

    } else {

        max_read = MIN(ctx->data_avail, count_bytes);
        if (max_read > 0u) {
            memcpy(buf, data + ctx->data_offset, max_read);
            ctx->data_avail -= max_read;
            ctx->data_offset += max_read;
        }
    }

    return max_read;
}

/*
 * php_ns_sapi_read_cookies() returns the Cookie header from the HTTP request header
 */

static char *php_ns_sapi_read_cookies(TSRMLS_D)
{
    ns_context *ctx = SG(server_context);
    char       *result = NULL;

    if (ctx->conn != NULL) {
        result = Ns_SetIGet(ctx->conn->headers, "Cookie");
    }
    return result;
}


static void php_ns_sapi_log_message(char *message, int UNUSED(syslog_type_int))
{
    Ns_Log(Error, "nsphp: %s", message);
}

static void php_ns_sapi_info(ZEND_MODULE_INFO_FUNC_ARGS)
{
    char        buf[512];
    long        uptime = Ns_InfoUptime();
    size_t      i;
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
    snprintf(buf, 511, "%ld day(s), %02ld:%02ld:%02ld",
             uptime / 86400,
             (uptime / 3600) % 24,
             (uptime / 60) % 60,
             uptime % 60);
    php_info_print_table_row(2, "Server uptime", buf);
    php_info_print_table_end();

    php_info_print_table_start();
    php_info_print_table_colspan_header(2, "HTTP Request Headers");
    php_info_print_table_row(2, "HTTP Request", ctx->conn->request.line);

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

static void php_ns_sapi_register_variables(zval *track_vars_array)
{
    const ns_context *ctx = SG(server_context);

    if (ctx->conn == NULL) {
        return;

    } else {
        size_t      i;
        Ns_DString  ds;
        char       *p, *value, c;

        Ns_DStringInit(&ds);
        for (i = 0; i < Ns_SetSize(ctx->conn->headers); i++) {
            const char *key = Ns_SetKey(ctx->conn->headers, i);

            value = Ns_SetValue(ctx->conn->headers, i);

            Ns_DStringSetLength(&ds, 0);
            Ns_DStringPrintf(&ds, "HTTP_%s", key);
            for (p = ds.string + 5; (c = *p); p++) {
                c = (char)toupper(c);
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
        Ns_DStringPrintf(&ds, "HTTP/%1.1f", ctx->conn->request.version);
        ADD_STRING("SERVER_PROTOCOL", ds.string);

        ADD_STRING("REQUEST_METHOD", (char *)ctx->conn->request.method);

        if (Ns_ConnHost(ctx->conn)) {
            Ns_DStringSetLength(&ds, 0);
            value = Ns_ConnLocationAppend(ctx->conn, &ds);
            /*
             * Strip protocol and port from the name
             */
            if ((p = strstr(value, "://"))) {
                value = p + 3;
                if ((p = strchr(value, ':')) != NULL) {
                    *p = 0;
                }
            }
            ADD_STRING("SERVER_NAME", value);
        }
        if (ctx->conn->request.query) {
            ADD_STRING("QUERY_STRING", ctx->conn->request.query);
        }

        ADD_STRING("SERVER_BUILDDATE", (char *)Ns_InfoBuildDate());
        ADD_STRING("REMOTE_ADDR", (char *)Ns_ConnPeerAddr(ctx->conn));

        Ns_DStringSetLength(&ds, 0);
        Ns_DStringPrintf(&ds, "%lu", Ns_InfoBootTime());
        ADD_STRING("SERVER_BOOTTIME", ds.string);

        Ns_DStringSetLength(&ds, 0);
        Ns_DStringPrintf(&ds, "%d", Ns_ConnPeerPort(ctx->conn));
        ADD_STRING("REMOTE_PORT", ds.string);

        Ns_DStringSetLength(&ds, 0);
        Ns_DStringPrintf(&ds, "%hu", Ns_ConnPort(ctx->conn));
        ADD_STRING("SERVER_PORT", ds.string);

        Ns_DStringSetLength(&ds, 0);
        Ns_DStringPrintf(&ds, "%" PRIuz, Ns_ConnContentLength(ctx->conn));
        ADD_STRING("CONTENT_LENGTH", ds.string);

        Ns_DStringSetLength(&ds, 0);
        Ns_DStringPrintf(&ds, "%s", SG(request_info).request_uri);
        if (ctx->conn->request.query) {
            Ns_DStringPrintf(&ds, "?%s", ctx->conn->request.query);
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
}

static int php_ns_sapi_startup(sapi_module_struct *sapi_module_ptr)
{
    if (php_module_startup(sapi_module_ptr, &nsphp_module_entry, 1) == FAILURE) {
        return FAILURE;
    } else {
        return SUCCESS;
    }
}

/*
 * The php_ns_request_handler() is called per request and handles everything for one request.
 */

static int php_ns_sapi_request_handler(const void *UNUSED(context), Ns_Conn *conn)
{
    Ns_DString       ds;
    ns_context       ctx;
    zend_file_handle file_handle;
    void *tsrm_ls_cache = tsrm_get_ls_cache();


    if (tsrm_ls_cache == NULL) {
        (void)ts_resource(0);
        ZEND_TSRMLS_CACHE_UPDATE();
        Ns_Log(Notice, "nsphp: refresh tsrm_ls_cache");
    }

    memset(&file_handle, 0, sizeof(zend_file_handle));

    Ns_DStringInit(&ds);
    Ns_UrlToFile(&ds, Ns_ConnServer(conn), conn->request.url);

    SG(request_info).path_translated = ds.string;

    SG(request_info).query_string = conn->request.query;
    SG(request_info).request_uri = (char *)conn->request.url;
    SG(request_info).request_method = conn->request.method;
    SG(request_info).proto_num = conn->request.version > 1.0 ? 1001 : 1000;
    SG(request_info).content_length = (zend_long)Ns_ConnContentLength(conn);
    SG(request_info).content_type = Ns_SetIGet(conn->headers, "Content-Type");
    SG(request_info).auth_user = STRDUP(Ns_ConnAuthUser(conn));
    SG(request_info).auth_password = STRDUP(Ns_ConnAuthPasswd(conn));
    SG(sapi_headers).http_response_code = 200;

    SG(server_context) = &ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.data_avail = (size_t)SG(request_info).content_length;
    ctx.conn = conn;

    file_handle.type = ZEND_HANDLE_FILENAME;
    file_handle.filename = SG(request_info).path_translated;
    file_handle.free_filename = 0;
    file_handle.opened_path = NULL;

    zend_first_try {
        php_request_startup(TSRMLS_C);
        php_execute_script(&file_handle TSRMLS_CC);
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

static int pdo_naviserver_stmt_dtor(pdo_stmt_t *stmt)
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

static int pdo_naviserver_stmt_execute(pdo_stmt_t *stmt)
{
    ns_pdo_handle *db = (ns_pdo_handle *)stmt->driver_data;

    switch (Ns_DbExec(db->db, db->sql)) {
    case NS_ERROR:
        zend_throw_exception_ex(php_pdo_get_exception(), 0, "%s", db->db->dsExceptionMsg.string);
        return 0;

    case NS_DML:
        return 0;

    case NS_ROWS:
        Ns_DbBindRow(db->db);
        stmt->column_count = (int)db->db->row->size;
        break;
    }
    return 1;
}

static int pdo_naviserver_stmt_fetch(pdo_stmt_t *stmt, enum pdo_fetch_orientation UNUSED(ori), long UNUSED(offset))
{
    ns_pdo_handle *db = (ns_pdo_handle *)stmt->driver_data;

    switch (Ns_DbGetRow(db->db, db->row)) {
    case NS_ERROR:
    case NS_END_DATA:
        return 0;
    }
    return 1;
}

static int pdo_naviserver_stmt_describe(pdo_stmt_t *stmt, int colno)
{
    ns_pdo_handle *db = (ns_pdo_handle *)stmt->driver_data;
    struct pdo_column_data *cols = stmt->columns;

    if (colno >= db->db->row->size) {
        return 0;
    }
    cols[colno].param_type = PDO_PARAM_STR;
    cols[colno].name = zend_string_init(db->db->row->fields[colno].name, strlen(db->db->row->fields[colno].name), 0);

    /*
     * We do not know column maxwidth, let's use size of the column value
     */
    cols[colno].maxlen = db->db->row->fields[colno].value ? strlen(db->db->row->fields[colno].value) : 0;
    cols[colno].precision = 0;

    return 1;
}

static int pdo_naviserver_stmt_get_col(pdo_stmt_t *stmt, int colno,
                                       char **ptr, unsigned long *len,
                                       int *UNUSED(caller_frees))
{
    ns_pdo_handle *db = (ns_pdo_handle *)stmt->driver_data;

    if (colno >= db->row->size) {
        return 0;
    }
    *ptr = db->row->fields[colno].value;
    *len = *ptr ? strlen(db->row->fields[colno].value) : 0;
    return 1;
}

static int pdo_naviserver_handle_fetch_error(pdo_dbh_t *dbh, pdo_stmt_t *UNUSED(stmt), zval *info)
{
    ns_pdo_handle *db = (ns_pdo_handle *)dbh->driver_data;
    add_next_index_string(info, db->db->dsExceptionMsg.string);

    return 1;
}

static int pdo_naviserver_handle_closer(pdo_dbh_t *dbh)
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

static int pdo_naviserver_handle_quoter(pdo_dbh_t *UNUSED(dbh),
                                        const char *unquoted, size_t unquotedlen,
                                        char **quoted, size_t *quotedlen,
                                        enum pdo_param_type UNUSED(paramtype))
{
    char  *q;
    size_t l = 1;

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

static int pdo_naviserver_handle_preparer(pdo_dbh_t *dbh,
                                          const char *sql, size_t UNUSED(sql_len),
                                          pdo_stmt_t *stmt,
                                          zval *UNUSED(driver_options))
{
    ns_pdo_handle *db = (ns_pdo_handle *)dbh->driver_data;

    ns_free(db->sql);
    db->sql = ns_strcopy(sql);
    stmt->driver_data = db;
    stmt->methods = &pdo_naviserver_stmt_methods;
    stmt->supports_placeholders = PDO_PLACEHOLDER_NONE;

    return 1;
}

static zend_long pdo_naviserver_handle_doer(pdo_dbh_t *dbh, const char *sql, size_t UNUSED(sql_len))
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

static int pdo_naviserver_handle_factory(pdo_dbh_t *dbh, zval *UNUSED(driver_options))
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
