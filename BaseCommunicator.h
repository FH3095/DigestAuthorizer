
#pragma once

#include "FCgiIO.h"
#include "cgicc/Cgicc.h"

class BaseCommunicator
{
public:
	enum AUTHORIZE_RESULT {
		NOT_PRESENT,
		SUCCESS,
		FAIL,
	};

	virtual bool isAuthorizationRespond() = 0;
	virtual AUTHORIZE_RESULT checkAuthorization() = 0;
	virtual void sendAuthorizationRequest() = 0;
};
