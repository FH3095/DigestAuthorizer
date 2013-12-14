
#pragma once

#include "BaseCommunicator.h"
#include "MainHandler.h"
#include "DigestPasswordCalculator.h"
#include <map>

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
	void splitAuthParameter();
	/// Returns the character AFTER nextCharacter
	std::string::size_type compareIgnoreSpace(const std::string& haystack, std::string::size_type start,
											const char* needle, const char nextCharacter);
	std::string::size_type skipSpace(const std::string& str,
									std::string::size_type start = 0,
									std::string::size_type end = std::string::npos);
	DigestPasswordCalculator passCalc;
	typedef std::map<std::string, std::string> AUTH_PARAMETER_MAP;
	AUTH_PARAMETER_MAP authParameter;
	bool parameterInitialized;
	bool parameterValid;
};
