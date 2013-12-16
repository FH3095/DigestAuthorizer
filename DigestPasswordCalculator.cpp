#include "DigestPasswordCalculator.h"

#include <openssl/rand.h>

std::chrono::steady_clock::duration DigestPasswordCalculator::conf_nonceValidTime = std::chrono::minutes(60);
bool DigestPasswordCalculator::conf_pseudoRandAllowed = true;
unsigned int DigestPasswordCalculator::conf_nonceKeyBytes = 32;
DigestPasswordCalculator::DigestRequestParameter::ALGORITHM DigestPasswordCalculator::conf_nonceAlgorithm = DigestPasswordCalculator::DigestRequestParameter::MD5;

std::vector<unsigned char> DigestPasswordCalculator::nonceKeyStart;
std::vector<unsigned char>DigestPasswordCalculator::nonceKeyEnd;
std::atomic<bool> DigestPasswordCalculator::initialized(false);

DigestPasswordCalculator::DigestPasswordCalculator()
{
	bool temp = false;
	if (initialized.compare_exchange_strong(temp, true))
	{
		nonceKeyStart.clear();
		nonceKeyStart.resize(conf_nonceKeyBytes, 0);
		generateRandom(nonceKeyStart.data(), conf_nonceKeyBytes);

		nonceKeyEnd.clear();
		nonceKeyEnd.resize(conf_nonceKeyBytes, 0);
		generateRandom(nonceKeyEnd.data(), conf_nonceKeyBytes);
	}
}

DigestPasswordCalculator::~DigestPasswordCalculator()
{
}

std::string DigestPasswordCalculator::generateNonce(const std::chrono::steady_clock::duration::rep timePoint)
{
	std::vector<unsigned char> tmpBuffer;
	tmpBuffer.reserve(nonceKeyStart.size() + nonceKeyEnd.size() + sizeof (timePoint));
	tmpBuffer.reserve(EVP_MAX_MD_SIZE + sizeof (timePoint));

	tmpBuffer.insert(tmpBuffer.begin(), nonceKeyStart.begin(), nonceKeyStart.end());
	tmpBuffer.insert(tmpBuffer.end(), reinterpret_cast<const unsigned char*>(&timePoint), reinterpret_cast<const unsigned char*>(&timePoint) + sizeof (timePoint));
	tmpBuffer.insert(tmpBuffer.end(), nonceKeyEnd.begin(), nonceKeyEnd.end());

	HashCalculator hc;
	hc.init(conf_nonceAlgorithm);
	hc.update(tmpBuffer.data(), tmpBuffer.size());
	tmpBuffer.clear();

	tmpBuffer.reserve(sizeof (timePoint) + EVP_MAX_MD_SIZE);
	tmpBuffer.insert(tmpBuffer.begin(), reinterpret_cast<const unsigned char*>(&timePoint), reinterpret_cast<const unsigned char*>(&timePoint) + sizeof (timePoint));
	hc.finalize(tmpBuffer);

	return convertBinToHex(tmpBuffer.data(), tmpBuffer.size());
}

DigestPasswordCalculator::CHECK_RESPONSE_RESULT DigestPasswordCalculator::checkResponseResult(const DigestResponseParameter& param, const std::string& userRealmPassword)
{
	std::chrono::steady_clock::duration::rep timePoint;
	convertHexToBin(reinterpret_cast<unsigned char*>(&timePoint), sizeof (timePoint), param.getNonce());

	std::chrono::steady_clock::duration timeDifference = std::chrono::steady_clock::now().time_since_epoch() - std::chrono::steady_clock::duration(timePoint);
	if (timeDifference < std::chrono::steady_clock::duration::zero())
	{
		// Hacking attempt, or steady_clock changed backwards (shouldn't happen)
		return FAILED;
	}
	if (param.getNonce().compare(generateNonce(timePoint)) != 0)
	{
		// Hacking attempt, or nonceKey changed (for example due to restart)
		return FAILED;
	}

	std::vector<unsigned char> tmpBuff;
	HashCalculator hashCalc;

	hashCalc.init(param.getAlgorithm());
	hashCalc.update(param.getMethod()).update(':').update(param.getUri());
	hashCalc.finalize(tmpBuff);
	std::string methodUri = convertBinToHex(tmpBuff.data(), tmpBuff.size());
	tmpBuff.clear();

	hashCalc.init(param.getAlgorithm());
	hashCalc.update(userRealmPassword)
			.update(':')
			.update(param.getNonce())
			.update(':')
			.update(param.getNc())
			.update(':')
			.update(param.getCnonce())
			.update(':')
			.update(reinterpret_cast<const unsigned char*>("auth"), 4)
			.update(':')
			.update(methodUri);
	hashCalc.finalize(tmpBuff);
	std::string response = convertBinToHex(tmpBuff.data(), tmpBuff.size());

	if (response.compare(param.getResponse()) != 0)
	{
		return FAILED;
	}

	if (timeDifference > conf_nonceValidTime)
	{
		return NONCE_STALE;
	}
	return SUCCESS;
}

void DigestPasswordCalculator::generateRandom(unsigned char* const result,
											  const unsigned int len)
{
	if (conf_pseudoRandAllowed)
	{
		if (-1 == RAND_pseudo_bytes(result, len))
		{
			throw std::runtime_error("Can't get pseudo-random bytes!");
		}
	}
	else
	{
		if (1 != RAND_bytes(result, len))
		{
			throw std::runtime_error("Can't get random bytes!");
		}
	}
}

std::string DigestPasswordCalculator::convertBinToHex(const unsigned char* const bin, const unsigned int bytes)
{
	static const std::vector<char> hexDigits({'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'});

	std::string result("");
	result.reserve(bytes * 2);
	for (unsigned int i = 0; i < bytes; ++i)
	{
		result.push_back(hexDigits.at((bin[i] >> 4) & 0xF));
		result.push_back(hexDigits.at(bin[i] & 0xF));
	}

	return result;
}

void DigestPasswordCalculator::convertHexToBin(unsigned char* target, const unsigned int bytes, const std::string& source, const unsigned int start)
{
	if (source.size() - start < bytes * 2)
	{
		std::string error("Can't convert from hex to binary, source-string is too short. Source-String: ");
		error += source;
		throw std::logic_error(error);
	}
	for (unsigned int i = 0; i < bytes; ++i)
	{
		char cur1 = source.at(start + i * 2);
		char cur2 = source.at(start + i * 2 + 1);
		target[i] = (convertHexToBin(cur1) << 4) | convertHexToBin(cur2);
	}
}

unsigned char DigestPasswordCalculator::convertHexToBin(const char data)
{
	if (data >= '0' && data <= '9')
	{
		return data - '0';
	}
	else if (data >= 'a' && data <= 'f')
	{
		return data - 'a' + 0xA;
	}
	else if (data >= 'A' && data <= 'F')
	{
		return data - 'A' + 0xA;
	}
	throw std::logic_error(std::string("Invalid Hex-Char: " + data));
}
