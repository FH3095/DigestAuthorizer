
#pragma once

#include "BaseAuthorizer.h"

class TestAuthorizer : public BaseAuthorizer
{
public:
	virtual bool checkAuthorization(const std::string& user, const std::string& pass, const BasePasswordCalculator& calc)
	{
		if(0 == user.compare("foo") && 0 == pass.compare("bar"))
		{
			return true;
		}
		return false;
	}
};
