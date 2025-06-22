#pragma once
#include <iostream>
#include <string>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <vector>
#include <math.h>

static std::vector<char> read_file_buf(const std::string& file_path) {
	std::ifstream file(file_path, std::ios::binary | std::ios::ate);
	if (file) {
		auto size = file.tellg();
		std::vector<char> buffer(size);
		file.seekg(0, std::ios::beg);
		file.read(buffer.data(), size);
		file.close();
		return buffer;
	}
	return {};
}