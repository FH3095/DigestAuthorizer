
#include "DigestCommunicator.h"

#include <algorithm>
#include <functional>
#include <locale>
#include <stdexcept>

DigestCommunicator::DigestCommunicator()
: parameterInitialized(false), parameterValid(false)
{
}

DigestCommunicator::~DigestCommunicator()
{
}

void DigestCommunicator::splitAuthParameter()
{
	static const std::vector<const char*> authParameterNames({"username", "realm", "nonce"});
	std::string auth = MainHandler::getThreadObjects().getEnv().get("HTTP_AUTHORIZATION");
	std::string lowerAuth(auth);
	std::transform(lowerAuth.begin(), lowerAuth.end(), lowerAuth.begin(),
				std::bind2nd(std::ptr_fun(&std::tolower<char>), std::locale("")));

	std::string::size_type startPos, endPos;
	startPos = compareIgnoreSpace(lowerAuth, 0, "digest", ' ');
	if (startPos == std::string::npos)
	{
		parameterValid = false;
		parameterInitialized = true;
		return;
	}
	while (startPos != std::string::npos && startPos < lowerAuth.size() - 1)
	{
		endPos = lowerAuth.find(',', startPos);
		if (endPos == lowerAuth.npos)
		{
			endPos = lowerAuth.size() - 1;
		}
		std::string::size_type valueStart;
		valueStart = compareIgnoreSpace(lowerAuth, startPos, "username", '=');
		if(valueStart!=std::string::npos)
		{
			
		}
	}
}

std::string::size_type DigestCommunicator::compareIgnoreSpace(const std::string& haystack,
															  std::string::size_type start,
															  const char* needle, const char nextCharacter)
{
	std::string::size_type pos = start;
	std::size_t needleLength = std::char_traits<char>::length(needle);
	// reserve one character after pos (it makes no sense to compare an empty string)
	pos = skipSpace(haystack, pos, haystack.size() - 1);

	if (haystack.compare(pos, needleLength, needle, needleLength) != 0)
	{
		return std::string::npos;
	}

	pos += needleLength;

	pos = skipSpace(haystack, pos);

	// Should match string end?
	if (nextCharacter == '\0')
	{
		return haystack.size() == pos ? pos : std::string::npos;
	}
	// We should search for spaces, so check last character
	if (nextCharacter == ' ')
	{
		return std::isspace(haystack.at(pos - 1)) ? pos - 1 : std::string::npos;
	}
	// Everything else needs more characters to match
	if (haystack.size() == pos)
	{
		return std::string::npos;
	}

	if (haystack.at(pos) != nextCharacter)
	{
		return std::string::npos;
	}
	return pos;
}

std::string::size_type DigestCommunicator::skipSpace(const std::string& str,
													 std::string::size_type start,
													 std::string::size_type end)
{
	if (std::string::npos == end || end > str.size())
	{
		end = str.size();
	}

	while (start < end && std::isspace(str.at(start)))
	{
		start++;
	}
	return start;
}
