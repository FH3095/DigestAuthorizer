
#pragma once

#include <openssl/md5.h>

class TestAuthorizer
{
public:
	virtual bool checkAuthorization(const std::string& user, const std::string& realm)
	{
		if(0 == user.compare("foo"))
		{
			return true;
		}
		return false;
	}
};
