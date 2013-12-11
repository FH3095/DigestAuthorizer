#include "DigestPasswordCalculator.h"

#include <memory>
#include <iterator>
#include <algorithm>
#include <openssl/rand.h>
#include <openssl/md5.h>
#include "MaintenanceWorker.h"

std::chrono::steady_clock::duration DigestPasswordCalculator::conf_noncesValidTime = std::chrono::minutes(60);

DigestPasswordCalculator::NONCES_MAP DigestPasswordCalculator::nonces;
std::chrono::steady_clock::time_point DigestPasswordCalculator::lastCleanup = std::chrono::steady_clock::now();
std::mutex DigestPasswordCalculator::noncesMutex;
std::atomic<bool> DigestPasswordCalculator::initialized(false);

DigestPasswordCalculator::DigestPasswordCalculator()
{
	nonceIsStale = false;
	bool temp = false;
	if (initialized.compare_exchange_strong(temp, true))
	{
		MaintenanceWorker::addCleanup(&cleanupNonces);
	}
}

DigestPasswordCalculator::~DigestPasswordCalculator()
{
}

std::string DigestPasswordCalculator::calculatePassword(const DigestPasswordParameter& parameter)
{
	static const char hexDigits[] = "0123456789ABCDEF";
	unsigned char rawMD5Result[MD5_DIGEST_LENGTH];
	MD5((const unsigned char*)parameter.getUserRealmPass().c_str(), parameter.getUserRealmPass().size(), rawMD5Result);

	std::string result("");
	result.reserve(MD5_DIGEST_LENGTH * 2);
	for (unsigned int i = 0; i < MD5_DIGEST_LENGTH; ++i)
	{
		result.push_back(hexDigits[(rawMD5Result[i] >> 4) & 0xF]);
		result.push_back(hexDigits[rawMD5Result[i] & 0xF]);
	}

	return result;
}

DigestPasswordCalculator::DigestPasswordParameter DigestPasswordCalculator::generateDigestParameter()
{
	return DigestPasswordParameter();
}

std::chrono::steady_clock::time_point DigestPasswordCalculator::cleanupNonces()
{
	const std::chrono::steady_clock::time_point curTime = std::chrono::steady_clock::now();
	std::lock_guard<std::mutex> lock(noncesMutex);

	for (NONCES_MAP::iterator it = nonces.begin(); it != nonces.end(); ++it)
	{
		if (it->second >= curTime)
		{
			it = nonces.erase(it);
		}
	}

	return std::chrono::steady_clock::time_point::max(); // We use the normal interval from MaintenanceWorker
}
