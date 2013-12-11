
#include <exception>
#include <iostream>

#include <thread>
#include <chrono>

#ifndef WIN32
#    include <unistd.h>
#else // WIN32
//#include <Windows.h>
#endif // WIN32

#include "cgicc/Cgicc.h"
#include "cgicc/HTTPHTMLHeader.h"
#include "cgicc/HTMLClasses.h"

#include "FCgiIO.h"
#include "MainHandler.h"
#include "BasicCommunicator.h"

using namespace std;
using namespace cgicc;

void dumpEnvironment(std::ostream& IO, const CgiEnvironment& env);

/*
FCGI_ROLE=AUTHORIZER
SERVER_SOFTWARE=lighttpd
SERVER_NAME=www.4fh.eu
GATEWAY_INTERFACE=CGI/1.1
SERVER_PORT=80
SERVER_ADDR=80.120.121.43
REMOTE_PORT=51240
REMOTE_ADDR=93.216.70.197
SCRIPT_FILENAME=/home/fh/domains/4fh.eu/www//cgi-bin/fcgiauth/
DOCUMENT_ROOT=/home/fh/domains/4fh.eu/www/
REQUEST_URI=/cgi-bin/fcgiauth/
QUERY_STRING=
REQUEST_METHOD=GET
REDIRECT_STATUS=200
SERVER_PROTOCOL=HTTP/1.1
HTTP_HOST=www.4fh.eu
HTTP_USER_AGENT=Mozilla/5.0 (Windows NT 6.1; WOW64; rv:25.0) Gecko/20100101 Firefox/25.0
HTTP_ACCEPT=text/html,application/xhtml+xml,application/xml;q=0.9,* / *;q=0.8
HTTP_ACCEPT_LANGUAGE=de-de,de;q=0.8,en-us;q=0.5,en;q=0.3
HTTP_ACCEPT_ENCODING=gzip, deflate
HTTP_DNT=1
HTTP_COOKIE=wow_extension=wotlk
HTTP_CONNECTION=keep-alive
HTTP_CACHE_CONTROL=max-age=0
HTTP_AUTHORIZATION=Basic ZmZmOmZmZg==
HTTP_AUTHORIZATION=Digest username="FH", realm="admin", nonce="b62ba78dd0fd82cfee1e8bcea9ae5122", uri="/admin/info.php", response="b3663ea3a119e71706e63d00f792450c", qop=auth, nc=00000002, cnonce="7ddaa6c484dc1e85"
 */

void callback()
{
	cgicc::FCgiIO& IO = MainHandler::getThreadObjects().getIO();
	cgicc::Cgicc& CGI = MainHandler::getThreadObjects().getCGI();
	BasicCommunicator bc;
	BasicCommunicator::AUTHORIZE_RESULT authorizeResult = bc.checkAuthorization();

	if (bc.NOT_PRESENT == authorizeResult)
	{
		bc.sendAuthorizationRequest();
	}
	if (authorizeResult != bc.SUCCESS)
	{
		return;
	}
	static int count = 0;

	try
	{
		// Output the HTTP headers for an HTML document, and the HTML 4.0 DTD info
		IO << HTTPHTMLHeader() << HTMLDoctype(HTMLDoctype::eStrict) << endl
				<< html().set("lang", "en").set("dir", "ltr") << endl;

		// Set up the page's header and title.
		IO << head() << endl
				<< title() << "GNU cgicc v" << CGI.getVersion() << title() << endl
				<< head() << endl;

		// Start the HTML body
		IO << body() << endl;

		// Print out a message
		IO << h1("Cgicc/FastCGI Test") << endl
				<< "count: " << count++ << br() << endl
				<< "Form Elements:" << br() << endl;

		dumpEnvironment(IO.err(), CGI.getEnvironment());
		// Close the document
		IO << body() << html();
	} catch (const exception&)
	{
		// handle error condition
	}
}

int
main(int /* argc */,
	 const char ** /* argv */,
	 char ** /* envp */)
{
	FCGX_Init();

	MainHandler::init(&callback, 1);
	MainHandler::run();
	MainHandler::free();

	return 0;
}

void dumpEnvironment(std::ostream& IO, const CgiEnvironment& env)
{
	IO << "Environment information from CgiEnvironment" << endl;

	IO << endl;

	IO << "Request Method: " << env.getRequestMethod() << endl;
	IO << "Path Info: " << env.getPathInfo() << endl;
	IO << "Path Translated: " << env.getPathTranslated() << endl;
	IO << "Script Name: " << env.getScriptName() << endl;
	IO << "HTTP Referrer: " << env.getReferrer() << endl;
	IO << "HTTP Cookie: " << env.getCookies() << endl;
	IO << "Query String: " << env.getQueryString() << endl;
	IO << "Content Length: " << env.getContentLength() << endl;
	IO << "Post Data: " << env.getPostData() << endl;
	IO << "Remote Host: " << env.getRemoteHost() << endl;
	IO << "Remote Address: " << env.getRemoteAddr() << endl;
	IO << "Authorization Type: " << env.getAuthType() << endl;
	IO << "Remote User: " << env.getRemoteUser() << endl;
	IO << "Remote Identification: " << env.getRemoteIdent() << endl;
	IO << "Content Type: " << env.getContentType() << endl;
	IO << "HTTP Accept: " << env.getAccept() << endl;
	IO << "User Agent: " << env.getUserAgent() << endl;
	IO << "Server Software: " << env.getServerSoftware() << endl;
	IO << "Server Name: " << env.getServerName() << endl;
	IO << "Gateway Interface: " << env.getGatewayInterface() << endl;
	IO << "Server Protocol: " << env.getServerProtocol() << endl;
	IO << "Server Port: " << env.getServerPort() << endl;
	IO << "HTTPS: " << (env.usingHTTPS() ? "true" : "false") << endl;
	IO << "Redirect Request: " << env.getRedirectRequest() << endl;
	IO << "Redirect URL: " << env.getRedirectURL() << endl;
	IO << "Redirect Status: " << env.getRedirectStatus() << endl;

	IO << endl;
}
