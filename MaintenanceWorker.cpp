
#include "MaintenanceWorker.h"

std::chrono::steady_clock::duration MaintenanceWorker::conf_maxCleanupSleep = std::chrono::seconds(60);
std::set<MaintenanceWorker::CLEANUP_FUNCTION> MaintenanceWorker::cleanups;
std::mutex MaintenanceWorker::cleanupsMutex;
std::thread MaintenanceWorker::worker;
bool MaintenanceWorker::shutdown = false;

void MaintenanceWorker::start()
{
	shutdown = false;
	std::thread tmp(&MaintenanceWorker::workerThread);
	worker.swap(tmp);
}

void MaintenanceWorker::doShutdown()
{
	shutdown = true;
	worker.join();
}

void MaintenanceWorker::addCleanup(CLEANUP_FUNCTION func)
{
	std::unique_lock<std::mutex> lock(cleanupsMutex);
	cleanups.insert(func);
}

void MaintenanceWorker::workerThread()
{
	while (!shutdown)
	{
		std::chrono::steady_clock::time_point tmp;
		std::chrono::steady_clock::time_point nextCleanup = std::chrono::steady_clock::now() + conf_maxCleanupSleep;

		std::unique_lock<std::mutex> lock(cleanupsMutex);
		for (CLEANUPS_SET::const_iterator it = cleanups.cbegin(); it != cleanups.cend(); ++it)
		{
			tmp = (*it)();
			if (nextCleanup > tmp)
			{
				nextCleanup = tmp;
			}
		}
		lock.unlock();

		std::this_thread::sleep_until(nextCleanup);
	}
}
