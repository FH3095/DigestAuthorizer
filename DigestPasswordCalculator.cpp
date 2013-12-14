#include "DigestPasswordCalculator.h"

#include <vector>
#include <stdexcept>
#include <stdint.h>
#include <openssl/rand.h>
#include <openssl/md5.h>
#include <openssl/sha.h>

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
		std::shared_ptr<unsigned char> temp;

		temp = generateRandom(conf_nonceKeyBytes);
		nonceKeyStart.clear();
		nonceKeyStart.insert(nonceKeyStart.begin(), temp.get(), temp.get() + conf_nonceKeyBytes);

		temp = generateRandom(conf_nonceKeyBytes);
		nonceKeyEnd.clear();
		nonceKeyEnd.insert(nonceKeyEnd.begin(), temp.get(), temp.get() + conf_nonceKeyBytes);
	}
}

DigestPasswordCalculator::~DigestPasswordCalculator()
{
}

std::string DigestPasswordCalculator::generateNonce()
{
	unsigned int tmpBufferSize = nonceKeyStart.size() + nonceKeyEnd.size() + sizeof (std::chrono::steady_clock::duration::rep);
	if (tmpBufferSize < 1024)
	{
		tmpBufferSize = 1024;
	}

	std::vector<unsigned char> tmpBuffer;
	tmpBuffer.reserve(tmpBufferSize);

	std::chrono::steady_clock::duration::rep timePoint = std::chrono::steady_clock::now().time_since_epoch().count();


	tmpBuffer.insert(tmpBuffer.begin(), nonceKeyStart.begin(), nonceKeyStart.end());
	tmpBuffer.insert(tmpBuffer.end(), reinterpret_cast<const unsigned char*>(&timePoint), reinterpret_cast<const unsigned char*>(&timePoint) + sizeof (timePoint));
	tmpBuffer.insert(tmpBuffer.end(), nonceKeyEnd.begin(), nonceKeyEnd.end());

	HASH_DATA_PAIR hashData = calcHash(conf_nonceAlgorithm, tmpBuffer.data(), tmpBuffer.size());

	tmpBuffer.clear();
	tmpBuffer.reserve(sizeof (timePoint) + hashData.second);
	tmpBuffer.insert(tmpBuffer.begin(), reinterpret_cast<const unsigned char*>(&timePoint), reinterpret_cast<const unsigned char*>(&timePoint) + sizeof (timePoint));
	tmpBuffer.insert(tmpBuffer.end(), hashData.first.get(), hashData.first.get() + hashData.second);

	return convertBinToHex(tmpBuffer.data(), tmpBuffer.size());
}

DigestPasswordCalculator::CHECK_RESPONSE_RESULT DigestPasswordCalculator::checkResponseResult(const DigestResponseParameter& param)
{
	return FAILED;
}

std::shared_ptr<unsigned char> DigestPasswordCalculator::generateRandom(const unsigned int len)
{
	std::shared_ptr<unsigned char> result(new unsigned char(len));

	if (conf_pseudoRandAllowed)
	{
		if (-1 == RAND_pseudo_bytes(result.get(), len))
		{
			throw std::runtime_error("Can't get pseudo-random bytes!");
		}
	}
	else
	{
		if (1 != RAND_bytes(result.get(), len))
		{
			throw std::runtime_error("Can't get random bytes!");
		}
	}

	return result;
}

DigestPasswordCalculator::HASH_DATA_PAIR DigestPasswordCalculator::calcHash(const DigestRequestParameter::ALGORITHM algo, const std::string& data)
{
	return calcHash(algo, reinterpret_cast<const unsigned char*>(data.c_str()), data.size());
}

DigestPasswordCalculator::HASH_DATA_PAIR DigestPasswordCalculator::calcHash(const DigestRequestParameter::ALGORITHM algo, const unsigned char* const data, const unsigned int len)
{
	HASH_DATA_PAIR result;

	switch (algo)
	{
	case DigestRequestParameter::MD5:
		result.second = MD5_DIGEST_LENGTH;
		result.first.reset(new unsigned char(result.second));
		MD5(data, len, result.first.get());
		break;
	case DigestRequestParameter::SHA256:
		result.second = SHA256_DIGEST_LENGTH;
		result.first.reset(new unsigned char(result.second));
		SHA256(data, len, result.first.get());
		break;
	case DigestRequestParameter::SHA512:
		result.second = SHA512_DIGEST_LENGTH;
		result.first.reset(new unsigned char(result.second));
		SHA512(data, len, result.first.get());
		break;
	default:
		throw std::logic_error("Unimplemented Digest-Hash-Algo: " + algo);
	}

	return result;
}

std::string DigestPasswordCalculator::convertBinToHex(const unsigned char* const bin, const unsigned int len)
{
	static const std::vector<char> hexDigits({'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'});

	std::string result("");
	result.reserve(len * 2);
	for (unsigned int i = 0; i < len; ++i)
	{
		result.push_back(hexDigits.at((bin[i] >> 4) & 0xF));
		result.push_back(hexDigits.at(bin[i] & 0xF));
	}

	return result;
}
