#pragma once
#include "SKRoot-linuxKernelRoot/patch_kernel_root/analyze/kernel_symbol_parser.h"
#include <iostream>
#include <vector>

struct KernelSymbolOffset {
	size_t _text_offset = 0;
	size_t _stext_offset = 0;
	size_t load_module_offset = 0;
};

class SymbolAnalyze
{
public:
	SymbolAnalyze(const std::vector<char> & file_buf);
	~SymbolAnalyze();

public:
	bool analyze_kernel_symbol();
	KernelSymbolOffset get_symbol_offset();
private:
	bool find_symbol_offset();
	uint64_t kallsyms_matching(const char* name, bool fuzzy = false);
	const std::vector<char>& m_file_buf;
	KernelSymbolParser m_kernel_sym_parser;
	KernelSymbolOffset m_kernel_sym_offset;
};