
#pragma once

#include <thread>
#include <mutex>
#include <chrono>
#include <set>

class MaintenanceWorker
{
public:
	typedef std::chrono::steady_clock::time_point (*CLEANUP_FUNCTION)();
	static void start();
	static void doShutdown();
	static void addCleanup(CLEANUP_FUNCTION func);
private:
	MaintenanceWorker()
	{	}
	static void workerThread();
	typedef std::set<CLEANUP_FUNCTION> CLEANUPS_SET;
	static CLEANUPS_SET cleanups;
	static std::thread worker;
	static std::mutex cleanupsMutex;
	static bool shutdown;
	
	static std::chrono::steady_clock::duration conf_maxCleanupSleep;
};
