#pragma once
#include <string>
#include "Types.h"

namespace QKD {
	class StatusDB
	{
	public:
		virtual bool GetStatusEntry(std::string key, StatusEntry** entry) = 0;
		virtual void PutStatusEntry(StatusEntry entry) = 0;
	};
}
