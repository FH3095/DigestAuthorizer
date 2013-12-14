
#pragma once

#include <string>
#include <memory>
#include <vector>
#include <chrono>
#include <atomic>
#include <stdexcept>
#include <openssl/evp.h>

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
		: qop(qop), algo(algo), nonce(nonce)
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

	private:
		const QOP_TYPE qop;
		const ALGORITHM algo;
		const std::string nonce;
	};

	class DigestResponseParameter : public DigestRequestParameter
	{
	public:

		DigestResponseParameter()
		: DigestRequestParameter()
		{
		}

		DigestResponseParameter(const QOP_TYPE qop, const ALGORITHM algo, const std::string& nonce, const std::string& method, const std::string& uri, const std::string& cnonce, const std::string& nc, const std::string& response)
		: DigestRequestParameter(qop, algo, nonce), method(method), uri(uri), cnonce(cnonce), nc(nc), response(response)
		{
		}

		inline const std::string& getMethod() const
		{
			return method;
		}

		inline const std::string& getUri() const
		{
			return uri;
		}

		inline const std::string& getCnonce() const
		{
			return cnonce;
		}

		inline const std::string& getNc() const
		{
			return nc;
		}

		inline const std::string& getResponse() const
		{
			return response;
		}

	private:
		const std::string method;
		const std::string uri;
		const std::string cnonce;
		const std::string nc;
		const std::string response;
	};

	class HashCalculator
	{
	public:

		HashCalculator()
		: mdCtx(NULL)
		{
		}

		virtual ~HashCalculator()
		{
			if (mdCtx != NULL)
			{
				EVP_MD_CTX_destroy(mdCtx);
				mdCtx = NULL;
			}
		}

		void init(const DigestRequestParameter::ALGORITHM algo)
		{
			const EVP_MD *md;
			switch (algo)
			{
			case DigestRequestParameter::MD5:
				md = EVP_md5();
				break;
			case DigestRequestParameter::SHA256:
				md = EVP_sha256();
				break;
			case DigestRequestParameter::SHA512:
				md = EVP_sha512();
				break;
			default:
				throw std::logic_error("Unimplemented Hash-Algo.");
			}
			mdCtx = EVP_MD_CTX_create();
			EVP_DigestInit_ex(mdCtx, md, NULL);
		}

		inline HashCalculator& update(const unsigned char* const data, const unsigned int len)
		{
			EVP_DigestUpdate(mdCtx, data, len);
			return *this;
		}

		inline HashCalculator& update(const std::string& data)
		{
			return update(reinterpret_cast<const unsigned char*>(data.c_str()), data.size());
		}

		inline HashCalculator& update(const char data)
		{
			return update(reinterpret_cast<const unsigned char*>(&data), 1);
		}

		unsigned int finalize(std::vector<unsigned char>& result)
		{
			unsigned int resultSize;
			std::vector<unsigned char>::size_type origSize = result.size();
			result.resize(result.size() + EVP_MAX_MD_SIZE, 0);
			EVP_DigestFinal_ex(mdCtx, &(result.at(origSize)), &resultSize);

			EVP_MD_CTX_destroy(mdCtx);
			mdCtx = NULL;

			result.resize(origSize + resultSize);
			return resultSize;
		}
	private:
		EVP_MD_CTX* mdCtx;
	};

	enum CHECK_RESPONSE_RESULT
	{
		FAILED, SUCCESS, NONCE_STALE,
	};

	DigestPasswordCalculator();
	virtual ~DigestPasswordCalculator();
	std::string generateNonce(const std::chrono::steady_clock::duration::rep timePoint = std::chrono::steady_clock::now().time_since_epoch().count());
	CHECK_RESPONSE_RESULT checkResponseResult(const DigestResponseParameter& param, const std::string& userRealmPassword);
private:
	static std::string convertBinToHex(const unsigned char* const bin, const unsigned int bytes);
	static void convertHexToBin(unsigned char* target, const unsigned int bytes, const std::string& source, const unsigned int start = 0);
	static inline unsigned char convertHexToBin(const char data);
	static std::shared_ptr<unsigned char> generateRandom(const unsigned int len);

	static std::vector<unsigned char> nonceKeyStart;
	static std::vector<unsigned char> nonceKeyEnd;
	static std::atomic<bool> initialized;

	static std::chrono::steady_clock::duration conf_nonceValidTime;
	static bool conf_pseudoRandAllowed;
	static unsigned int conf_nonceKeyBytes;
	static DigestRequestParameter::ALGORITHM conf_nonceAlgorithm;
};
