
#include "httpd.h"
#include "http_core.h"
#include "http_protocol.h"
#include "http_request.h"

#include <sstream>
#include <string>
#include <format>
#include <map>


static void register_hooks(apr_pool_t* pool);
static int hello_handler(request_rec* r);
static std::string helloWorld(char* args);
static void parseParameter(std::map<std::string, std::string>& map, const std::string keyValuePair);


module AP_MODULE_DECLARE_DATA mod_hello_module = 
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

static int hello_handler(request_rec* r)
{
    // If the handler is NULL or different from "hello-handler", we will not handle the request.
    //
    if (!r->handler || strcmp(r->handler, "hello-handler")) return (DECLINED);

    ap_set_content_type(r, "text/html");
    ap_rprintf(r, "%s", helloWorld(r->args).c_str());

    return OK;
}


static std::string helloWorld(char* args) {

    std::stringstream sstream;

    sstream << "<html><p>Hello World!</p>";


    if (args) {
        
        std::map<std::string, std::string> map { };

        std::string parameters { args };
        std::string delimiter = "&";
        size_t start = 0;
        size_t end = 0;

        std::string keyValuePair { };
        size_t n = 1;
        while ((end = parameters.find(delimiter, start)) != std::string::npos)
        {
            keyValuePair = parameters.substr(start, end - start);
            parseParameter(map, keyValuePair);
            
            start = end + delimiter.length();
            n++;            
        }
        
        // At this point, we will no longer find anymore delimiters, so the final portion of the string
        // is the last parameter.
        //
        keyValuePair = parameters.substr(start);
        parseParameter(map, keyValuePair);

        // Output all of the parameters to the page:
        //
        sstream << "<p>The following query parameters were parsed:</p>";
        n = 0;
        for (std::map<std::string, std::string>::iterator it = map.begin(); it != map.end(); it++)
        {
            sstream << "<p>" << n << ": parameters[\"" << it->first << "\"]=\"" << it->second << "\"</p>";
            n++;
        }
    }
    else {
        sstream << "<p>No query string!</p>";
    }

    sstream << "</html>";
    return sstream.str();
}

/// @brief Parses the key-value pair (parameter) and inserts or updates the provided map.
/// @param map the map to update with the key-value pair, if the provided value is correctly formed
/// @param keyValuePair the parameter to parse (of the form key=value)
static void parseParameter(std::map<std::string, std::string>& map, const std::string keyValuePair)
{
    size_t pos = 0;
    if ((pos = keyValuePair.find('=')) == std::string::npos)
        return; // The parameter is malformed, skip it.
    
    std::string key = keyValuePair.substr(0, pos);
    std::string value = keyValuePair.substr(pos + 1);

    // Note: this can update the query parameter it if occurs multiple times.
    map[key] = value;
}