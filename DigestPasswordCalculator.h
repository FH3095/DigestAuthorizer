
#pragma once

#include <string>
#include <map>
#include <chrono>
#include <mutex>

#include "BasePasswordCalculator.h"

class DigestPasswordCalculator : public BasePasswordCalculator
{
public:

	class DigestParameter
	{
	public:

		enum QOP_TYPE
		{
			AUTH,
			//AUTH_INT,
		};

		enum ALGORITHM
		{
			MD5,
			//MD5_SESS,
		};
		
		DigestParameter()
		: qop(AUTH), algo(MD5), nonce("")
		{
		}

		DigestParameter(QOP_TYPE qop, ALGORITHM algo, std::string& nonce)
		: qop(qop), algo(algo), nonce(nonce)
		{
		}

		const QOP_TYPE qop;
		const ALGORITHM algo;
		const std::string nonce;
	};
	DigestPasswordCalculator();
	virtual ~DigestPasswordCalculator();
	static virtual DigestParameter generateDigestParameter();
	virtual void prepareCalculatePassword(const DigestParameter& parameter);
	virtual std::string calculatePassword(const std::string& pass);
	inline virtual bool isNonceStale()
	{	return nonceIsStale;	}
private:
	void cleanupNonces();
	DigestParameter parameter;
	bool parameterSet;
	bool nonceIsStale;
	typedef std::map<std::string, std::chrono::steady_clock::time_point> NONCES_MAP;
	static NONCES_MAP nonces;
	static std::chrono::steady_clock::time_point lastCleanup;
	static std::mutex noncesMutex;
};
