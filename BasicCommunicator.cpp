#include "BasicCommunicator.h"
#include "MainHandler.h"

#include <iostream>
#include <openssl/md5.h>

BasicCommunicator::BasicCommunicator()
{
}

BasicCommunicator::~BasicCommunicator()
{
}

bool BasicCommunicator::isAuthorizationRespond()
{
	return !MainHandler::getThreadObjects().getEnv().get("HTTP_AUTHORIZATION").empty();
}

BasicCommunicator::AUTHORIZE_RESULT BasicCommunicator::checkAuthorization()
{
	if (isAuthorizationRespond())
	{
		return AUTHORIZE_RESULT::SUCCESS;
	} else
	{
		return AUTHORIZE_RESULT::NOT_PRESENT;
	}
}

void BasicCommunicator::sendAuthorizationRequest()
{
	cgicc::FCgiIO& IO = MainHandler::getThreadObjects().getIO();
	IO << "Status: 401 Unauthorized" << std::endl
			<< "WWW-Authenticate: Basic realm=\"Test\"" << std::endl
			<< std::endl;
}
