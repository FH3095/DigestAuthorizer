
#pragma once

#include <string>
#include <map>
#include <chrono>
#include <mutex>

class BasePasswordCalculator
{
public:
	BasePasswordCalculator();
	virtual ~BasePasswordCalculator();
	virtual std::string calculatePassword(const std::string& pass) = 0;
};
