/*
   Copyright 2011 Ask Bjørn Hansen
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at
       http://www.apache.org/licenses/LICENSE-2.0
   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_vhost.h"
#include "apr_strings.h"

#include <ctype.h> // isspace
#include <arpa/inet.h>
module AP_MODULE_DECLARE_DATA ishttps_module;
APR_DECLARE_OPTIONAL_FN(int, ssl_is_https, (conn_rec *));

typedef struct {
    int                enable;
    int                sethttps;
    int                setport;
    const char         *orig_scheme;
    const char         *https_scheme;
    int                orig_port;
} ishttps_server_cfg;

typedef struct {
    request_rec *r;
} ishttps_cleanup_rec;


static void *ishttps_create_server_cfg(apr_pool_t *p, server_rec *s) {
    ishttps_server_cfg *cfg = (ishttps_server_cfg *)apr_pcalloc(p, sizeof(ishttps_server_cfg));
    if (!cfg)
        return NULL;

    cfg->enable = 0;

    /* server_rec->server_scheme only available after 2.2.3 */
    #if AP_SERVER_MINORVERSION_NUMBER > 1 && AP_SERVER_PATCHLEVEL_NUMBER > 2
    cfg->orig_scheme = s->server_scheme;
    #endif

    cfg->https_scheme = apr_pstrdup(p, "https");
    cfg->orig_port = s->port;

    return (void *)cfg;
}


static const char *ishttps_enable(cmd_parms *cmd, void *dummy, int flag) {
    server_rec *s = cmd->server;
    ishttps_server_cfg *cfg = (ishttps_server_cfg *)ap_get_module_config(s->module_config,
                                                                   &ishttps_module);

    cfg->enable = flag;
    return NULL;
}

static const char *ishttps_sethttps(cmd_parms *cmd, void *dummy, int flag) {
    server_rec *s = cmd->server;
    ishttps_server_cfg *cfg = (ishttps_server_cfg *)ap_get_module_config(s->module_config,
                                                                   &ishttps_module);

    cfg->sethttps = flag;
    return NULL;
}

static const char *ishttps_setport(cmd_parms *cmd, void *dummy, int flag) {
    server_rec *s = cmd->server;
    ishttps_server_cfg *cfg = (ishttps_server_cfg *)ap_get_module_config(s->module_config,
                                                                   &ishttps_module);

    cfg->setport = flag;
    return NULL;
}

static int ishttps_post_read_request(request_rec *r) {

    ishttps_server_cfg *cfg = (ishttps_server_cfg *)ap_get_module_config(r->server->module_config,
                                                                   &ishttps_module);

    if (!cfg->enable)
        return DECLINED;

    /* this overcomes an issue when mod_rewrite causes this to get called again
       and the environment value is lost for HTTPS. This is the only thing that
       is lost and we do not need to process any further after restoring the
       value. */
    const char *ishttps_https = apr_table_get(r->connection->notes, "ishttps_https");
    if (ishttps_https) {
        apr_table_set(r->subprocess_env, "HTTPS", ishttps_https);
        return DECLINED;
    }

    if (cfg->sethttps) {
        const char *httpsvalue, *scheme;
        if ((httpsvalue = apr_table_get(r->headers_in, "X-Forwarded-HTTPS")) ||
            (httpsvalue = apr_table_get(r->headers_in, "X-HTTPS"))) {
            apr_table_set(r->connection->notes, "ishttps_https", httpsvalue);
            apr_table_set(r->subprocess_env   , "HTTPS"     , httpsvalue);

            scheme = cfg->https_scheme;
        } else if ((httpsvalue = apr_table_get(r->headers_in, "X-Forwarded-Proto"))
                   && (strcmp(httpsvalue, cfg->https_scheme) == 0)) {
            apr_table_set(r->connection->notes, "ishttps_https", "on");
            apr_table_set(r->subprocess_env   , "HTTPS"     , "on");
            scheme = cfg->https_scheme;
        } else {
            scheme = cfg->orig_scheme;
        }
        #if AP_SERVER_MINORVERSION_NUMBER > 1 && AP_SERVER_PATCHLEVEL_NUMBER > 2
        r->server->server_scheme = scheme;
        #endif
    }   

     if (cfg->setport) {
        const char *portvalue;
        if ((portvalue = apr_table_get(r->headers_in, "X-Forwarded-Port")) ||
            (portvalue = apr_table_get(r->headers_in, "X-Port"))) {
            r->server->port    = atoi(portvalue);
            r->parsed_uri.port = r->server->port;
        } else {
            r->server->port = cfg->orig_port;
        }
    }    

    return OK;
}

static const command_rec ishttps_cmds[] = {
    AP_INIT_FLAG(
                 "ISHTTPS_Enable",
                 ishttps_enable,
                 NULL,
                 RSRC_CONF,
                 "Enable mod_ishttps"
                 ),
    AP_INIT_FLAG(
                 "ISHTTPS_SetHttps",
                 ishttps_sethttps,
                 NULL,
                 RSRC_CONF,
                 "Let mod_ishttps set the HTTPS environment variable from the X-HTTPS header"
                 ),
    AP_INIT_FLAG(
                 "ISHTTPS_SetPort",
                 ishttps_setport,
                 NULL,
                 RSRC_CONF,
                 "Let mod_ishttps set the server port from the X-Port header"
                 ),
    { NULL }
};

static int ssl_is_https(conn_rec *c) {
    return apr_table_get(c->notes, "ishttps_https") != NULL;
}

static void ishttps_register_hooks(apr_pool_t *p) {
    ap_hook_post_read_request(ishttps_post_read_request, NULL, NULL, APR_HOOK_REALLY_FIRST);

    /* this will only work if mod_ssl is not loaded */
    if (APR_RETRIEVE_OPTIONAL_FN(ssl_is_https) == NULL)
        APR_REGISTER_OPTIONAL_FN(ssl_is_https);
}

module AP_MODULE_DECLARE_DATA ishttps_module = {
    STANDARD20_MODULE_STUFF,
    NULL,                       /* Per-directory configuration handler */
    NULL,                       /* Merge handler for per-directory configurations */
    ishttps_create_server_cfg,  /* Per-server configuration handler */
    NULL,                       /* Merge handler for per-server configurations */
    ishttps_cmds,               /* Any directives we may have for httpd */
    ishttps_register_hooks,     /* Our hook registering function */
};
