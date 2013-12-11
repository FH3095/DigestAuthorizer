
#include "MainHandler.h"

#include <exception>

MainHandler::ThreadObjectsMapType MainHandler::threadObjectsMap;
MainHandler::RequestArrayType MainHandler::requests;
MainHandler::RequestsPtrQueueType MainHandler::freeRequests;
MainHandler::RequestsPtrQueueType MainHandler::todoRequests;
std::mutex MainHandler::freeRequestsMutex;
std::condition_variable MainHandler::freeRequestsNotifier;
std::mutex MainHandler::todoRequestsMutex;
std::condition_variable MainHandler::todoRequestsNotifier;
std::thread MainHandler::acceptThread;
std::atomic<bool> MainHandler::shutdown(false);
MainHandler::HandleRequestCallback MainHandler::callback = NULL;

void MainHandler::init(HandleRequestCallback callback, unsigned int numThreads, int socket, int flags)
{
	if (requests.size() > 0)
	{
		throw std::logic_error("MainHandler is already initialized.");
	}
	if (numThreads < 1)
	{
		throw std::underflow_error("Can't use less than 1 thread.");
	}

	MainHandler::callback = callback;
	requests.resize(numThreads);
	requests.shrink_to_fit();
	for (unsigned int i = 0; i < numThreads; ++i)
	{
		FCGX_InitRequest(&(requests[i]), socket, flags);
		freeRequests.push(&(requests[i]));

		std::thread(&MainHandler::handleRequestThread).detach();
	}
}

void MainHandler::run(bool waitForFinish)
{
	testInitialized();

	std::thread tmp(&MainHandler::acceptRequestsThread);
	MainHandler::acceptThread.swap(tmp);

	if (waitForFinish)
	{
		acceptThread.join();
	}
}

void MainHandler::free()
{
	testInitialized();
	shutdown.store(true);
	callback = NULL;
	while (todoRequests.size() > 0)
	{
		todoRequests.pop();
	}
	while (freeRequests.size() > 0)
	{
		freeRequests.pop();
	}

	for (unsigned int i = 0; i < requests.size(); ++i)
	{
		FCGX_Free(&(requests[i]), 1);
	}
	requests.clear();

	threadObjectsMap.clear();
	todoRequestsNotifier.notify_all();
}

void MainHandler::acceptRequestsThread()
{
	FCGX_Request* curRequest;
	std::unique_lock<std::mutex> lock(freeRequestsMutex);
	lock.unlock();

	while (shutdown.load() == false)
	{
		lock.lock();
		freeRequestsNotifier.wait(lock, &MainHandler::acceptThreadHasWorkTodo);
		if (true == shutdown.load())
		{
			break;
		}

		curRequest = freeRequests.front();
		freeRequests.pop();
		lock.unlock();

		if (FCGX_Accept_r(curRequest) != 0)
		{
			break;
		}
		handleRequest(*curRequest);
	}
}

void MainHandler::handleRequest(FCGX_Request& request)
{
	testInitialized();

	std::unique_lock<std::mutex> lock(todoRequestsMutex);
	todoRequests.push(&request);
	todoRequestsNotifier.notify_one();
}

void MainHandler::handleRequestThread()
{
	while (true)
	{
		std::unique_lock<std::mutex> lock(todoRequestsMutex);
		todoRequestsNotifier.wait(lock, &MainHandler::requestThreadHasWorkTodo);
		if (true == shutdown.load())
		{
			break;
		}

		FCGX_Request* request = todoRequests.front();
		todoRequests.pop();
		lock.unlock();

		try
		{
			cgicc::FCgiIO IO(*request);
			ThreadObjects objects(IO);
			ThreadObjectsMapType::iterator mapIterator =
					threadObjectsMap.insert(ThreadObjectsMapType::value_type(std::this_thread::get_id(), objects)).first;

			try
			{
				callback();
			} catch (std::exception& e)
			{
				IO.err() << "FastCGI: Error while processing: " << e.what() << std::endl;
			} catch (...)
			{
				IO.err() << "FastCGI: Unknown error while processing." << std::endl;
			}

			threadObjectsMap.erase(mapIterator);
			FCGX_Finish_r(request);

			std::unique_lock<std::mutex> lock(freeRequestsMutex);
			freeRequests.push(request);
			freeRequestsNotifier.notify_one();
		} catch (std::exception& e)
		{
			std::cerr << "FastCGI: MainHandler: Error: " << e.what() << std::endl;
		} catch (...)
		{
			std::cerr << "FastCGI: MainHandler: Unknown error" << std::endl;
		}
	}
}

void MainHandler::testInitialized()
{
	if (requests.size() < 1)
	{
		throw std::logic_error("MainHandler is not initialized.");
	}
}
