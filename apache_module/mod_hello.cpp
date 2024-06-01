
#include "httpd.h"
#include "http_core.h"
#include "http_protocol.h"
#include "http_request.h"
#include "apr_strings.h"

#include <sstream>
#include <string>
#include <format>
#include <map>


static void register_hooks(apr_pool_t* pool);

// Handlers
//
static int hello_handler(request_rec* r);
static int reset_handler(request_rec* r);

// Helper functions
//

/// @brief Parses the POSTed JSON data from the request body, storing the result in the provided setValue parameter.
/// @param r the request_rec containing the request body.
/// @param setValue the location to store the setValue.
/// @return True if the body could be parsed, otherwise, false.
static bool parseJSONBody(request_rec* r, int& setValue);

/// @brief Parses the POSTed form data from the reqest body, storing the result in the provided setValue parameter.
/// @param r the request_rec containing the request body.
/// @param setValue the location to store the setValue.
/// @return True if the body could be parsed, otherwise, false.
static bool parseFormBody(request_rec* r, int& setValue);

/// @brief Performs a case-insensitive compare between two strings.
/// @param s1 the first string.
/// @param s2 the second string.
/// @return True, if the strings are equal, disregarding case, otherwise, false.
static bool icompare(const std::string_view& s1, const std::string_view& s2);

/// @brief Checks if there is a matching request header with the provided key and value.
/// @param key the key of the request header to look for.
/// @param value the value of the request header to match.
/// @param startsWidth if true, ignores matching against additional characters not found in the provided value.
/// @return True if the key/value pair is found in the request headers, otherwise false.
static bool hasRequestHeader(const request_rec* r, std::string key, std::string value, bool startsWith = false);

/// @brief Checks if there is a matching request header with the provided key and returns the associated value.
/// @param key the key of the request header to look for.
/// @return returns the associated value, or an empty string if not found.
static std::string getRequestHeader(const request_rec* r, std::string key);

// Debugging functions
//

/// @brief Parses args as a query string of the form (path?param1=a&param2=b), creating a map of all key-value pairs.
/// @param args the query string.
/// @param map the map.
/// @remark 
///     If the query string includes multiple parameters of the same key, the last one has precedence.
///     If there are parameters, but there is a ?, then the map will be empty.
///     If a key-value pair is malformed, it will be skipped.
static void parseQueryString(const char* args, std::map<std::string, std::string>& map);

/// @brief Parses the key-value pair (parameter) and inserts or updates the provided map.
/// @param map the map to update with the key-value pair, if the provided value is correctly formed.
/// @param keyValuePair the parameter to parse (of the form key=value).
static void parseParameter(const std::string keyValuePair, std::map<std::string, std::string>& map);


// Web API functions
//

static std::string helloWorld();
static std::string setCounter(int n);
static std::string resetCounter();


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
    ap_hook_handler(reset_handler, NULL, NULL, APR_HOOK_LAST);
}

int counter = 0;

static int hello_handler(request_rec* r)
{
    if (!r->handler || strcmp(r->handler, "hello-handler")) return DECLINED; // Not processed by this handler.

    ap_set_content_type(r, "text/html");

    if (strcmp(r->method, "POST") == 0)
    {
        if (hasRequestHeader(r, "Content-Type", "application/x-www-form-urlencoded", true)) {
            // If we are using an HTML form (e.g. with a submit button), data will come as a form request body.
            int setValue;
            if (!parseFormBody(r, setValue)) {
                return HTTP_BAD_REQUEST;
            }
            
            std::string response = setCounter(setValue);
            ap_rputs(response.c_str(), r);
            return OK;
        }
        else if (hasRequestHeader(r, "Content-Type", "application/json", true) ||
                 hasRequestHeader(r, "Content-Type", "text/plain", true)) {
            // For a traditional RESTful architecture, we can use a POST request with a JSON request body.
            // This way, the front-end does not need to use HTML forms.
            // Note: Due to CORS failing preflight checks for application/json (an unsupported content-type), we also attempt
            // to handle text/plain as if it were JSON. This is not perfect, but might be suitable depending on the deployment.
            int setValue;
            if (!parseJSONBody(r, setValue)) {
                return HTTP_BAD_REQUEST;
            }

            std::string response = setCounter(setValue);
            ap_rputs(response.c_str(), r);
            return OK;
        }
    }
    else if (strcmp(r->method , "GET") == 0)
    {
        // We can use the following function to check any query string parameters.
        //
        // std::map<std::string, std::string> map { };
        // parseQueryString(r->args, map);

        std::string response = helloWorld();
        ap_rputs(response.c_str(), r);
        return OK;
    }

    return HTTP_NOT_FOUND;
}

static int reset_handler(request_rec* r)
{
    if (!r->handler || strcmp(r->handler, "reset-handler")) return DECLINED; // Not processed by this handler.

    if (strcmp(r->method, "POST") != 0)
    {
        return HTTP_BAD_REQUEST; // Only POST is supported for /reset endpoint.
    }

    ap_set_content_type(r, "text/html");
    std::string repsonse = resetCounter();
    ap_rputs(repsonse.c_str(), r);

    return OK;
}

static std::string setCounter(int n) {
    counter = n;
    return std::format("<html><p>Hello World! Counter: {}</p></html>", counter);
}

static std::string resetCounter() {
    counter = 0;
    return { std::format("<html><p>Hello World! Counter: {}</p></html>", counter) };
}

static std::string helloWorld() {

    std::stringstream sstream;

    sstream << "<html>";
    sstream << std::format("<p>Hello World! Counter: {}</p>", counter);

    // Below we output forms that can be used to make the set/reset requests.
    sstream << R"(
        <form action="hello">
            <input type="number" name="setValue"><button type="submit" formmethod="post">Set</button><br><br>
        </form>
        <form action="reset" method="post">
            <button type="submit">Reset Counter</button>
        </form>
    )";

    sstream << "</html>";
    return sstream.str();
}

static bool parseJSONBody(request_rec* r, int& setValue) {
    if (ap_setup_client_block(r, REQUEST_CHUNKED_ERROR)) {
        return false;
    }

    char* bodyBuffer;

    // Read the request body into memory
    //
    if (ap_should_client_block(r)) {
        char readBuffer[HUGE_STRING_LEN];
        apr_off_t rsize, bytesRead, readPos = 0;
        apr_off_t length = r->remaining;

        bodyBuffer = static_cast<char*>(apr_pcalloc(r->pool, static_cast<apr_size_t>(length + 1)));

        while ((bytesRead = ap_get_client_block(r, readBuffer, sizeof(readBuffer))) > 0) {
            if ((readPos + bytesRead) > length) {
                rsize = length - readPos; // cap read bytes so it doesn't exceed the length
            }
            else {
                rsize = bytesRead;
            }

            memcpy(static_cast<char*>(bodyBuffer) + readPos, readBuffer, rsize);
            readPos += bytesRead;
        }
    }

    // Now that the request body is in memory, we should be able to parse it.
    //
    // Since it's a very simple json we can parse directly instead of depending on a library.
    //
    std::string body = std::string(bodyBuffer);

    std::erase(body, '{');
    std::erase(body, '}');
    std::erase(body, ' ');
    std::erase(body, '\t');
    std::erase(body, '\r');
    std::erase(body, '\n');

    size_t pos;
    if ((pos = body.find(':')) == std::string::npos)
        return false; // JSON is malformed.

    std::string value = body.substr(pos + 1);
    std::erase(value, '\"');

    try {
        setValue = std::stoi(value);
    }
    catch (...) {
        return false; // JSON is malformed.
    }

    return true;
}

static bool parseFormBody(request_rec* r, int& setValue) {

    apr_array_header_t* postData;
    if (ap_parse_form_data(r, NULL, &postData, -1, HUGE_STRING_LEN) != OK || !postData)
        return false;

    
    apr_off_t len;
    apr_size_t size;
    char* buffer;
    std::map<std::string, std::string> map { };

    while (postData && !apr_is_empty_array(postData)) {
        ap_form_pair_t* pair = static_cast<ap_form_pair_t*>(apr_array_pop(postData));
        apr_brigade_length(pair->value, 1, &len);
        size = static_cast<apr_size_t>(len);
        buffer = reinterpret_cast<char*>(apr_palloc(r->pool, size + 1));
        apr_brigade_flatten(pair->value, buffer, &size);
        buffer[len] = 0;

        map[apr_pstrdup(r->pool, pair->name)] = buffer;
    }

    if (!map.contains("setValue")) {
        return false;
    }

    std::string strSetValue = map["setValue"];    
    try {
        setValue = std::stoi(strSetValue);
    }
    catch (...) {
        return false; // Form body is malformed.
    }

    return true;
}

static bool icompare(const std::string_view& s1, const std::string_view& s2)
{
    if (s1.length() != s2.length())
        return false;

    // Perform a case insensitive check by converting both strings to the same case (e.g. lower)
    //
    for (size_t index = 0; index < s1.length(); index++) {
        if (std::tolower(static_cast<unsigned char>(s1[index])) != std::tolower(static_cast<unsigned char>(s2[index])))
            return false;
    }
    return true;
}

static bool hasRequestHeader(const request_rec* r, std::string key, std::string value, bool startsWith)
{
    const apr_array_header_t* headersTable = apr_table_elts(r->headers_in);
    apr_table_entry_t* headers = (apr_table_entry_t*)headersTable->elts;

    for (int i = 0; i < headersTable->nelts; i++) {

        std::string headerValue { headers[i].val }; 
        if (startsWith) {
            // Short of writing a full method to check the content type which sometimes omits the charset,
            // we can just check if the value begins with the same set of characters.
            // It would be better to implement a new function for specifically handling edge cases concerning
            // the content type.
            headerValue = headerValue.substr(0, std::min(value.length(), headerValue.length()));
        }


        // Header keys are case insensitive
        if (icompare(key, headers[i].key)) {
            // Found the desired key, check the value for a match.
            return (value.compare(headerValue) == 0);
        }
    }

    return false;
}

static std::string getRequestHeader(const request_rec* r, std::string key)
{
    const apr_array_header_t* headersTable = apr_table_elts(r->headers_in);
    apr_table_entry_t* headers = (apr_table_entry_t*)headersTable->elts;

    for (int i = 0; i < headersTable->nelts; i++) {
        if (key.compare(headers[i].key) == 0) {
            // Found the desired key, return the value.
            return headers[i].val;
        }
    }
    return "";
}

static void parseQueryString(const char* args, std::map<std::string, std::string>& map)
{
    if (!args) return; // If there is no query string, do not attempt to parse and insert into the map.

    std::string parameters { args };
    std::string delimiter = "&";
    size_t start = 0;
    size_t end = 0;

    std::string keyValuePair { };
    while ((end = parameters.find(delimiter, start)) != std::string::npos)
    {
        keyValuePair = parameters.substr(start, end - start);
        parseParameter(keyValuePair, map);
        
        start = end + delimiter.length();
    }
    
    // At this point, we will no longer find anymore delimiters, so the final portion of the string
    // is the last parameter.
    //
    keyValuePair = parameters.substr(start);
    parseParameter(keyValuePair, map);
}

static void parseParameter(const std::string keyValuePair, std::map<std::string, std::string>& map)
{
    size_t pos = 0;
    if ((pos = keyValuePair.find('=')) == std::string::npos)
        return; // The parameter is malformed, skip it.
    
    std::string key = keyValuePair.substr(0, pos);
    std::string value = keyValuePair.substr(pos + 1);

    // Note: this can update the query parameter it if occurs multiple times.
    map[key] = value;
}