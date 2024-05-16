
#include "httpd.h"
#include "http_core.h"
#include "http_protocol.h"
#include "http_request.h"

#include <string>


static void register_hooks(apr_pool_t *pool);
static int hello_handler(request_rec *r);
static std::string helloWorld();


module AP_MODULE_DECLARE_DATA mod_hello = 
{
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    register_hooks
};

static void register_hooks(apr_pool_t *pool)
{
    ap_hook_handler(hello_handler, NULL, NULL, APR_HOOK_LAST);
}

static int hello_handler(request_rec *r)
{
    // If the handler is NULL or different from "hello-handler", we will not handle the request.
    //
    if (!r->handler || strcmp(r->handler, "hello-handler")) return (DECLINED);

    ap_set_content_type(r, "text/html");
    ap_rprintf(r, "%s", helloWorld().c_str());

    return OK;
}


static std::string helloWorld() {
    return "<html><p>Hello World!</p></html>";
}