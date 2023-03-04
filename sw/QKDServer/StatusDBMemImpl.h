#pragma once
#include "StatusDB.h"
#include <boost/multi_index_container.hpp>
#include <boost/multi_index/hashed_index.hpp>
#include <boost/multi_index/member.hpp>

using namespace boost::multi_index;

using statusEntry_map = multi_index_container<QKD::StatusEntry, indexed_by<
	hashed_unique<tag<struct by_key1>, member<QKD::StatusEntry, std::string, &QKD::StatusEntry::key1>>,
	hashed_unique<tag<struct by_key2>, member<QKD::StatusEntry, std::string, &QKD::StatusEntry::key2>>>>;

namespace QKD {
	class StatusDBMemImpl : public StatusDB
	{
	public:
		bool GetStatusEntry(std::string key, StatusEntry** entry);
		void PutStatusEntry(StatusEntry entry);

	private:
		statusEntry_map _statusDB;
	};
}
