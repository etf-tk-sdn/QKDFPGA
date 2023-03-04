#pragma once

#include "server/http/https_server.h"
#include "string/string_utils.h"
#include "utility/singleton.h"

#include <boost/multi_index_container.hpp>
#include <boost/multi_index/hashed_index.hpp>
#include "QKDAuthDB.h"

using namespace boost::multi_index;

class QKDDatabaseAPI: public CppCommon::Singleton<QKDDatabaseAPI>
{
    friend CppCommon::Singleton<QKDDatabaseAPI>;

public:
    QKDAuthDB* qkdDB;
};

