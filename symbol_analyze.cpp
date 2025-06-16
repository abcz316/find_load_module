#pragma once
#include "symbol_analyze.h"

SymbolAnalyze::SymbolAnalyze(const std::vector<char>& file_buf) : m_file_buf(file_buf), m_kernel_sym_parser(file_buf)
{
}

SymbolAnalyze::~SymbolAnalyze()
{
}

bool SymbolAnalyze::analyze_kernel_symbol() {
	if (!m_kernel_sym_parser.init_kallsyms_lookup_name()) {
		std::cout << "Failed to initialize kallsyms lookup name" << std::endl;
		return false;
	}
	if (!find_symbol_offset()) {
		std::cout << "Failed to find symbol offset" << std::endl;
		return false;
	}
	return true;
}

KernelSymbolOffset SymbolAnalyze::get_symbol_offset() {
	return m_kernel_sym_offset;
}

bool SymbolAnalyze::find_symbol_offset() {
	m_kernel_sym_offset._text_offset = kallsyms_matching("_text");
	m_kernel_sym_offset._stext_offset = kallsyms_matching("_stext");
	m_kernel_sym_offset.load_module_offset = kallsyms_matching("load_module");
	if (m_kernel_sym_offset.load_module_offset == 0) {
		m_kernel_sym_offset.load_module_offset = kallsyms_matching("load_module", true);
	}
	return m_kernel_sym_offset.load_module_offset;
}

uint64_t SymbolAnalyze::kallsyms_matching(const char* name, bool fuzzy) {
	if (fuzzy) {
		auto map = m_kernel_sym_parser.kallsyms_lookup_names_like(name);
		if (map.size()) {
			return map.begin()->second;
		}
		return 0;
	}
	return m_kernel_sym_parser.kallsyms_lookup_name(name);
}