#include "DigestPasswordCalculator.h"

#include <memory>
#include <openssl/rand.h>
#include <openssl/md5.h>
#include "MaintenanceWorker.h"

std::chrono::steady_clock::duration DigestPasswordCalculator::conf_nonceValidTime = std::chrono::minutes(60);
unsigned int DigestPasswordCalculator::conf_nonceBytes = MD5_DIGEST_LENGTH;
bool DigestPasswordCalculator::conf_pseudoRandAllowed = true;

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
	unsigned int dataLength;
	std::unique_ptr<unsigned char> resultData;

	switch (parameter.getAlgorithm())
	{
	case DigestPasswordParameter::MD5:
		dataLength = MD5_DIGEST_LENGTH;
		resultData.reset(new unsigned char(dataLength));
		MD5((const unsigned char*)parameter.getUserRealmPass().c_str(), parameter.getUserRealmPass().size(), resultData.get());
		break;
	default:
		throw std::logic_error("Unimplemented Digest-Hash-Algo: " + parameter.getAlgorithm());
	}

	return convertBinToHex(resultData.get(), dataLength);
}

DigestPasswordCalculator::DigestPasswordParameter DigestPasswordCalculator::generateDigestParameter(const DigestPasswordParameter::QOP_TYPE qop, const DigestPasswordParameter::ALGORITHM algo, const std::string& realm, const std::string& user, const std::string& password)
{
	std::unique_ptr<unsigned char> nonceData(new unsigned char(conf_nonceBytes));

	if (conf_pseudoRandAllowed)
	{
		if (-1 == RAND_pseudo_bytes(nonceData.get(), conf_nonceBytes))
		{
			throw std::runtime_error("Can't get pseudo-random bytes!");
		}
	}
	else
	{
		if (1 != RAND_bytes(nonceData.get(), conf_nonceBytes))
		{
			throw std::runtime_error("Can't get random bytes!");
		}
	}

	std::string nonce = convertBinToHex(nonceData.get(), conf_nonceBytes);

	std::lock_guard<std::mutex> lock(noncesMutex);
	nonces[nonce] = std::chrono::steady_clock::now() + conf_nonceValidTime;

	return DigestPasswordParameter(qop, algo, nonce, realm, user, password);
}

std::string DigestPasswordCalculator::convertBinToHex(const unsigned char* bin, const unsigned int len)
{
	static const char hexDigits[] = "0123456789ABCDEF";

	std::string result("");
	result.reserve(len * 2);
	for (unsigned int i = 0; i < len; ++i)
	{
		result.push_back(hexDigits[(bin[i] >> 4) & 0xF]);
		result.push_back(hexDigits[bin[i] & 0xF]);
	}

	return result;
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
