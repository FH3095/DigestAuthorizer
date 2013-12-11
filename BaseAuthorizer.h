
#pragma once

#include <string>

#include "FCgiIO.h"
#include "cgicc/Cgicc.h"

class BaseAuthorizer
{
public:
	virtual bool checkAuthorization(const std::string& user, const std::string& pass, const BasePasswordCalculator& calc) = 0;
};
