#include "DigestPasswordCalculator.h"

#include <openssl/rand.h>

DigestPasswordCalculator::NONCES_MAP DigestPasswordCalculator::nonces;
std::chrono::steady_clock::time_point DigestPasswordCalculator::lastCleanup = std::chrono::steady_clock::now();
std::mutex DigestPasswordCalculator::noncesMutex;

DigestPasswordCalculator::DigestPasswordCalculator()
: BasePasswordCalculator()
{
	parameterSet = false;
	nonceIsStale = false;
}

DigestPasswordCalculator::~DigestPasswordCalculator()
{
}

void DigestPasswordCalculator::prepareCalculatePassword(const DigestParameter& parameter)
{
	this->parameter = parameter;
	parameterSet = true;
}
