
#pragma once

#include <thread>
#include <map>
#include <queue>
#include <vector>
#include <atomic>
#include <mutex>
#include <condition_variable>

#include "FCgiIO.h"
#include "cgicc/Cgicc.h"
#include <fstream>

#include "CgiEnvironmentExtended.h"

class MainHandler
{
public:
	typedef void (*HandleRequestCallback)();

	class ThreadObjects
	{
	public:

		ThreadObjects(cgicc::FCgiIO& _IO)
		: IO(_IO), CGI(&_IO), env(IO, CGI.getEnvironment())
		{
		}

		ThreadObjects(ThreadObjects& other)
		: IO(other.getIO()), CGI(&IO), env(IO, CGI.getEnvironment())
		{
		}

		inline cgicc::Cgicc& getCGI()
		{
			return CGI;
		}

		inline cgicc::FCgiIO& getIO()
		{
			return IO;
		}

		inline CgiEnvironmentExtended& getEnv()
		{
			return env;
		}
	private:
		cgicc::FCgiIO& IO;
		cgicc::Cgicc CGI;
		CgiEnvironmentExtended env;
	};

	static void init(HandleRequestCallback callback, unsigned int numThreads = 1, int socket = 0, int flags = 0);
	static void run(bool waitForFinish = true);
	static void free();
	static void handleRequest(FCGX_Request& request);

	static std::thread& getAcceptThread()
	{
		return acceptThread;
	}

	static ThreadObjects& getThreadObjects()
	{
		return threadObjectsMap.at(std::this_thread::get_id());
	}
protected:
	static void testInitialized();
	static void acceptRequestsThread();
	static void handleRequestThread();
private:

	MainHandler()
	{
	}

	static bool requestThreadHasWorkTodo()
	{
		return todoRequests.size() > 0 || shutdown;
	}

	static bool acceptThreadHasWorkTodo()
	{
		return freeRequests.size() > 0 || shutdown;
	}
	typedef std::map<std::thread::id, ThreadObjects&> ThreadObjectsMapType;
	typedef std::vector<FCGX_Request> RequestArrayType;
	typedef std::queue<FCGX_Request*> RequestsPtrQueueType;
	static ThreadObjectsMapType threadObjectsMap;
	static RequestArrayType requests;
	static RequestsPtrQueueType freeRequests;
	static RequestsPtrQueueType todoRequests;

	static std::thread acceptThread;
	static std::mutex freeRequestsMutex;
	static std::condition_variable freeRequestsNotifier;
	static std::mutex todoRequestsMutex;
	static std::condition_variable todoRequestsNotifier;

	static std::atomic<bool> shutdown;
	static HandleRequestCallback callback;
};
