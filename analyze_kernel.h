#pragma once
#include "kernel_symbol_parser.h"
#include <iostream>
#include <vector>

struct KernelSymbolOffset {
	size_t _text_offset = 0;
	size_t _stext_offset = 0;
	size_t load_module_offset = 0;
};

class AnalyzeKernel
{
public:
	AnalyzeKernel(const std::vector<char> & file_buf);
	~AnalyzeKernel();

public:
	bool analyze_kernel_symbol();
	KernelSymbolOffset get_symbol_offset();
private:
	bool find_symbol_offset();
	const std::vector<char>& m_file_buf;
	KernelSymbolParser m_kernel_sym_parser;
	KernelSymbolOffset m_kernel_sym_offset;
};