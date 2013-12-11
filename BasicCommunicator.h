
#pragma once

#include "BaseCommunicator.h"

class BasicCommunicator : public BaseCommunicator
{

public:
	BasicCommunicator();
	virtual ~BasicCommunicator();

	virtual bool isAuthorizationRespond();
	virtual void sendAuthorizationRequest();
	virtual AUTHORIZE_RESULT checkAuthorization();
};
