#pragma once
#include "analyze_kernel.h"

AnalyzeKernel::AnalyzeKernel(const std::vector<char>& file_buf) : m_file_buf(file_buf), m_kernel_sym_parser(file_buf)
{
}

AnalyzeKernel::~AnalyzeKernel()
{
}

bool AnalyzeKernel::analyze_kernel_symbol() {
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

KernelSymbolOffset AnalyzeKernel::get_symbol_offset() {
	return m_kernel_sym_offset;
}

bool AnalyzeKernel::find_symbol_offset() {
	m_kernel_sym_offset._text_offset = m_kernel_sym_parser.kallsyms_lookup_name("_text");
	m_kernel_sym_offset._stext_offset = m_kernel_sym_parser.kallsyms_lookup_name("_stext");
	m_kernel_sym_offset.load_module_offset = m_kernel_sym_parser.kallsyms_lookup_name("load_module");
	if (m_kernel_sym_offset.load_module_offset == 0) {
		m_kernel_sym_offset.load_module_offset = m_kernel_sym_parser.kallsyms_lookup_name("load_module", true);
	}
	return m_kernel_sym_offset.load_module_offset;
}