
#pragma once

#include <string>
#include <map>
#include <chrono>
#include <mutex>
#include <atomic>

class DigestPasswordCalculator
{
public:

	class DigestPasswordParameter
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

		DigestPasswordParameter()
		: qop(AUTH), algo(MD5), nonce(""), userRealmPass("")
		{
		}

		DigestPasswordParameter(const QOP_TYPE qop, const ALGORITHM algo, const std::string& nonce, const std::string& realm, const std::string& user, const std::string& pass)
		: DigestPasswordParameter(qop, algo, nonce, user + ":" + realm + ":" + pass)
		{
		}

		DigestPasswordParameter(const QOP_TYPE qop, const ALGORITHM algo, const std::string& nonce, const std::string userRealmPass)
		: qop(qop), algo(algo), nonce(nonce), userRealmPass(userRealmPass)
		{
		}

		inline QOP_TYPE getQop() const
		{
			return qop;
		}

		inline ALGORITHM getAlgorithm() const
		{
			return algo;
		}

		inline const std::string& getNonce() const
		{
			return nonce;
		}

		inline const std::string& getUserRealmPass() const
		{
			return userRealmPass;
		}

	private:
		QOP_TYPE qop;
		ALGORITHM algo;
		std::string nonce;
		std::string userRealmPass;
	};

	DigestPasswordCalculator();
	virtual ~DigestPasswordCalculator();
	static DigestPasswordParameter generateDigestParameter(const DigestPasswordParameter::QOP_TYPE qop, const DigestPasswordParameter::ALGORITHM algo, const std::string& realm, const std::string& user, const std::string& password);
	virtual std::string calculatePassword(const DigestPasswordParameter& parameter);

	inline virtual bool isNonceStale()
	{
		return nonceIsStale;
	}
private:
	static std::chrono::steady_clock::time_point cleanupNonces();
	static std::string calcHash(DigestPasswordParameter::ALGORITHM algo,const std::string& data);
	static std::string convertBinToHex(const unsigned char* bin, const unsigned int len);
	bool nonceIsStale;
	typedef std::map<std::string, std::chrono::steady_clock::time_point> NONCES_MAP;
	static NONCES_MAP nonces;
	static std::chrono::steady_clock::time_point lastCleanup;
	static std::mutex noncesMutex;
	static std::atomic<bool> initialized;

	static std::chrono::steady_clock::duration conf_nonceValidTime;
	static unsigned int conf_nonceBytes;
	static bool conf_pseudoRandAllowed;
};
