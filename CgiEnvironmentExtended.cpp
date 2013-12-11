
#include "CgiEnvironmentExtended.h"

CgiEnvironmentExtended::CgiEnvironmentExtended(cgicc::CgiInput& _input, const cgicc::CgiEnvironment& _env)
: CgiEnvironment(_env), input(_input)
{
}

CgiEnvironmentExtended::~CgiEnvironmentExtended()
{
}

std::string CgiEnvironmentExtended::get(const char* name)
{
	ENV_VALUES_MAP::const_iterator it = envValues.find(name);
	if (envValues.end() != it)
	{
		return it->second;
	}

	std::string result = input.getenv(name);
	if (!result.empty())
	{
		envValues[std::string(name)] = result;
	}
	return result;
}
