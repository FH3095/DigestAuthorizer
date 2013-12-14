
#pragma once

#include <string>
#include <utility>
#include <memory>
#include <vector>
#include <chrono>
#include <atomic>

class DigestPasswordCalculator
{
public:

	class DigestRequestParameter
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
			SHA256,
			//SHA256_SESS,
			SHA512,
			//SHA512_SESS,
		};

		DigestRequestParameter()
		: qop(AUTH), algo(MD5), nonce("")
		{
		}

		DigestRequestParameter(const QOP_TYPE qop, const ALGORITHM algo, const std::string& nonce)
		: DigestRequestParameter(qop, algo, nonce)
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

		inline std::string getNonce() const
		{
			return nonce;
		}

	public:
		const QOP_TYPE qop;
		const ALGORITHM algo;
		const std::string nonce;
	};

	class DigestResponseParameter : public DigestRequestParameter
	{

		DigestResponseParameter()
		: DigestRequestParameter()
		{
		}

		DigestResponseParameter(const QOP_TYPE qop, const ALGORITHM algo, const std::string& nonce, const std::string& method, const std::string& uri, const std::string& cnonce, const std::string& nc)
		: DigestRequestParameter(qop, algo, nonce), method(method), uri(uri), cnonce(cnonce), nc(nc)
		{
		}

		inline std::string getMethod() const
		{
			return method;
		}

		inline std::string getUri() const
		{
			return uri;
		}

		inline std::string getCnonce() const
		{
			return cnonce;
		}

		inline std::string getNc() const
		{
			return nc;
		}

	public:
		const std::string method;
		const std::string uri;
		const std::string cnonce;
		const std::string nc;
	};

	enum CHECK_RESPONSE_RESULT
	{
		FAILED, SUCCESS, NONCE_STALE,
	};

	DigestPasswordCalculator();
	virtual ~DigestPasswordCalculator();
	static std::string generateNonce();
	virtual CHECK_RESPONSE_RESULT checkResponseResult(const DigestResponseParameter& param);
private:
	typedef std::pair<std::shared_ptr<unsigned char>, unsigned int> HASH_DATA_PAIR;
	static std::shared_ptr<unsigned char> generateRandom(const unsigned int len);
	static HASH_DATA_PAIR calcHash(const DigestRequestParameter::ALGORITHM algo, const std::string& data);
	static HASH_DATA_PAIR calcHash(const DigestRequestParameter::ALGORITHM algo, const unsigned char* const data, const unsigned int len);
	static std::string convertBinToHex(const unsigned char* const bin, const unsigned int len);

	static std::vector<unsigned char> nonceKeyStart;
	static std::vector<unsigned char> nonceKeyEnd;
	static std::atomic<bool> initialized;

	static std::chrono::steady_clock::duration conf_nonceValidTime;
	static bool conf_pseudoRandAllowed;
	static unsigned int conf_nonceKeyBytes;
	static DigestRequestParameter::ALGORITHM conf_nonceAlgorithm;
};
