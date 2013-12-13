
#pragma once

#include "BaseCommunicator.h"
#include "MainHandler.h"

class DigestCommunicator : public BaseCommunicator
{
public:

	DigestCommunicator();
	virtual ~DigestCommunicator();

	virtual bool isAuthorizationRespond()
	{
		return !MainHandler::getThreadObjects().getEnv().get("HTTP_AUTHORIZATION").empty();
	}

	virtual AUTHORIZE_RESULT checkAuthorization()
	{
		if (isAuthorizationRespond())
		{
			return AUTHORIZE_RESULT::SUCCESS;
		}
		else
		{
			return AUTHORIZE_RESULT::NOT_PRESENT;
		}
	}

	virtual void sendAuthorizationRequest()
	{
		cgicc::FCgiIO& IO = MainHandler::getThreadObjects().getIO();
		IO << "Status: 401 Unauthorized" << std::endl
				<< "WWW-Authenticate: Basic realm=\"Test\"" << std::endl
				<< std::endl;
	}
private:
	bool nonceStale;
};
