
#pragma once

#include <map>
#include <cgicc/Cgicc.h>

class CgiEnvironmentExtended : public cgicc::CgiEnvironment
{
public:
	CgiEnvironmentExtended(cgicc::CgiInput& _input, const cgicc::CgiEnvironment& _env);
	virtual ~CgiEnvironmentExtended();

	virtual std::string get(const char* name);
private:
	typedef std::map<std::string, std::string> ENV_VALUES_MAP;
	ENV_VALUES_MAP envValues;
	cgicc::CgiInput& input;
};
