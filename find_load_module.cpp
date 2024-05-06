// patch_kernel_root.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include "base_func.h"
#include "analyze_kernel.h"

int main(int argc, char* argv[]) {
	++argv;
	--argc;

	std::cout << "本工具用于查找在aarch64 Linux内核文件中load_module的位置" << std::endl;

	if (argc < 1) {
		std::cout << "无输入文件" << std::endl;
		system("pause");
		return 0;
	}
	const char* file_path = argv[0];
	std::vector<char> file_buf = read_file_buf(file_path);
	if (!file_buf.size()) {
		std::cout << "Fail to open file:" << file_path << std::endl;
		system("pause");
		return 0;
	}

	AnalyzeKernel analyze_kernel(file_buf);
	if (!analyze_kernel.analyze_kernel_symbol()) {
		std::cout << "Failed to analyze kernel symbols" << std::endl;
		system("pause");
		return 0;
	}
	KernelSymbolOffset sym = analyze_kernel.get_symbol_offset();

	std::cout << "_text: 0x" << sym._text_offset << std::endl;
	std::cout << "_stext: 0x" << sym._stext_offset << std::endl;
	std::cout << "load_module: 0x" << sym.load_module_offset << std::endl;
	system("pause");
	return 0;
}