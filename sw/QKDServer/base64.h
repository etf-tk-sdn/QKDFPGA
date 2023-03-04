#pragma once
#ifndef _BASE64_H_
#define _BASE64_H_

#include <vector>
#include <string>

std::string base64_encode(uint8_t const* buf, unsigned int bufLen);

#endif