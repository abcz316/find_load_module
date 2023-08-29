

#include <stdio.h>
#include <iostream>
#include <malloc.h>
#include <vector>
#include "3rdparty/find_xrefs.h"
#pragma comment(lib, "3rdparty/capstone-4.0.2-win64/capstone.lib")

struct partInfo {
	size_t pos = 0;
	char partHex[4 * 4] = { 0 };
};
char* GetFileBuf(const char* lpszFilePath, int& nSize) {
	FILE* pFile = fopen(lpszFilePath, "rb");
	if (!pFile) {
		return NULL;
	}
	fseek(pFile, 0, SEEK_END);
	nSize = ftell(pFile);
	rewind(pFile);

	char* buffer = (char*)malloc(sizeof(char) * nSize);
	if (!buffer) {
		return NULL;
	}

	size_t result = fread(buffer, 1, nSize, pFile);
	if ((int)result != nSize) {
		free(buffer);
		return NULL;
	}
	fclose(pFile);
	
	return buffer;
}

const char* FindBytes(const char* pWaitSearchAddress, size_t nLen, const char* bForSearch, size_t ifLen) {
	for (size_t i = 0; i < nLen; i++) {
		char* pData = (char*)(pWaitSearchAddress + i);
		char* bTemForSearch = (char*)bForSearch;
		bool bContinue = false;
		for (size_t y = 0; y < ifLen; y++, ++pData, ++bTemForSearch) {
			if (*pData != *bTemForSearch) {
				bContinue = true;
				break;
			}
		}
		if (bContinue) {
			continue;
		}
		return pWaitSearchAddress + i;
	}
	return 0;
}

void RemoveDuplicatePartInfo(std::vector<partInfo>& vPartInfo) {
	std::vector<partInfo> vResult;
	for (const partInfo& part : vPartInfo) {
		bool bShow = false;
		for (const partInfo& item : vResult) {
			if (item.pos == part.pos) {
				bShow = true;
				break;
			}
		}
		if (!bShow) {
			vResult.push_back(part);
		}
	}
	vPartInfo.clear();
	for (const partInfo& part : vResult) {
		vPartInfo.push_back(part);
	}
}

void RemoveDuplicateFuncStartResultMap(std::map<size_t, std::shared_ptr<size_t>>& resultMap) {
	std::map<size_t, std::shared_ptr<size_t>> newResultMap;
	for (auto iter1 = resultMap.begin(); iter1 != resultMap.end(); iter1++) {
		bool exist = false;
		if (iter1->second && *iter1->second) {
			for (auto iter2 = newResultMap.begin(); iter2 != newResultMap.end(); iter2++) {
				if (iter2->second && *iter2->second == *iter1->second) {
					exist = true;
					break;
				}
			}
		}
		if (exist) {
			continue;
		}
		newResultMap[iter1->first] = iter1->second;
	}
	resultMap = newResultMap;
}


void SearchFeature1(char* image, size_t size) {

	std::vector<partInfo> vSearch;

	char featureORR[4] = { '\xE1','\xFB','\x40','\xB2' };

	char* pAddress = (char*)FindBytes(image, size, featureORR, 4);
	while (pAddress) {
		partInfo info;
		info.pos = pAddress - image;
		vSearch.push_back(info);

		pAddress += 4;
		pAddress = (char*)FindBytes(pAddress, size - ((size_t)pAddress - (size_t)image), featureORR, 4);
	}

	char featureMOV[4] = { '\x01','\x00','\xF0','\x92' };
	pAddress = (char*)FindBytes(image, size, featureMOV, 4);
	while (pAddress) {
		partInfo info;
		info.pos = pAddress - image;
		vSearch.push_back(info);

		pAddress += 4;
		pAddress = (char*)FindBytes(pAddress, size - ((size_t)pAddress - (size_t)image), featureMOV, 4);
	}

	RemoveDuplicatePartInfo(vSearch);
	std::map<size_t, std::shared_ptr<size_t>> result_map;
	for (size_t i = 0; i < vSearch.size(); i++) {
		result_map[vSearch[i].pos] = std::make_shared<size_t>();
	}
	find_func_haed_link(image, size, result_map);
	RemoveDuplicateFuncStartResultMap(result_map);
	printf_head_result_map(result_map);
}
void SearchFeature2(char* image, size_t size) {
	std::vector<partInfo> vSearchTotal;

	{
		char feature1[31 * 4] = {
		'\xE0','\x03','\x11','\x32',  
		'\xE1','\x03','\x11','\x32',  
		'\xE2','\x03','\x11','\x32',  
		'\xE3','\x03','\x11','\x32',  
		'\xE4','\x03','\x11','\x32',  
		'\xE5','\x03','\x11','\x32',  
		'\xE6','\x03','\x11','\x32',  
		'\xE7','\x03','\x11','\x32',  
		'\xE8','\x03','\x11','\x32',  
		'\xE9','\x03','\x11','\x32',  
		'\xEA','\x03','\x11','\x32',  
		'\xEB','\x03','\x11','\x32',  
		'\xEC','\x03','\x11','\x32',  
		'\xED','\x03','\x11','\x32',  
		'\xEE','\x03','\x11','\x32',  
		'\xEF','\x03','\x11','\x32',  
		'\xF0','\x03','\x11','\x32',  
		'\xF1','\x03','\x11','\x32',  
		'\xF2','\x03','\x11','\x32',  
		'\xF3','\x03','\x11','\x32',  
		'\xF4','\x03','\x11','\x32',  
		'\xF5','\x03','\x11','\x32',  
		'\xF6','\x03','\x11','\x32',  
		'\xF7','\x03','\x11','\x32',  
		'\xF8','\x03','\x11','\x32',  
		'\xF9','\x03','\x11','\x32',  
		'\xFA','\x03','\x11','\x32',  
		'\xFB','\x03','\x11','\x32',  
		'\xFC','\x03','\x11','\x32',  
		'\xFD','\x03','\x11','\x32',  
		'\xFE','\x03','\x11','\x32',  
		};
		char feature2[31 * 4] = {
			'\xE0','\x43','\x11','\x32',  
			'\xE1','\x43','\x11','\x32',  
			'\xE2','\x43','\x11','\x32',  
			'\xE3','\x43','\x11','\x32',  
			'\xE4','\x43','\x11','\x32',  
			'\xE5','\x43','\x11','\x32',  
			'\xE6','\x43','\x11','\x32',  
			'\xE7','\x43','\x11','\x32',  
			'\xE8','\x43','\x11','\x32',  
			'\xE9','\x43','\x11','\x32',  
			'\xEA','\x43','\x11','\x32',  
			'\xEB','\x43','\x11','\x32',  
			'\xEC','\x43','\x11','\x32',  
			'\xED','\x43','\x11','\x32',  
			'\xEE','\x43','\x11','\x32',  
			'\xEF','\x43','\x11','\x32',  
			'\xF0','\x43','\x11','\x32',  
			'\xF1','\x43','\x11','\x32',  
			'\xF2','\x43','\x11','\x32',  
			'\xF3','\x43','\x11','\x32',  
			'\xF4','\x43','\x11','\x32',  
			'\xF5','\x43','\x11','\x32',  
			'\xF6','\x43','\x11','\x32',  
			'\xF7','\x43','\x11','\x32',  
			'\xF8','\x43','\x11','\x32',  
			'\xF9','\x43','\x11','\x32',  
			'\xFA','\x43','\x11','\x32',  
			'\xFB','\x43','\x11','\x32',  
			'\xFC','\x43','\x11','\x32',  
			'\xFD','\x43','\x11','\x32',  
			'\xFE', '\x43', '\x11', '\x32',

		};
		std::vector<partInfo> vSearch;

		for (int i = 0; i < 31; i++) {
			char* pAddress = (char*)FindBytes(image, size, &feature1[i * 4], 4);
			while (pAddress) {

				if ((size - (size_t)pAddress - (size_t)image) < 16) {
					break;
				}
				partInfo info;
				info.pos = pAddress - image;
				memcpy(&info.partHex, (void*)pAddress, sizeof(info.partHex));
				vSearch.push_back(info);

				pAddress += 4;
				pAddress = (char*)FindBytes(pAddress, size - ((size_t)pAddress - (size_t)image), &feature1[i * 4], 4);
			}
		}
		for (int i = 0; i < 31; i++) {
			char* pAddress = (char*)FindBytes(image, size, &feature2[i * 4], 4);
			while (pAddress) {
				if ((size - (size_t)pAddress - (size_t)image) < 16) {
					break;
				}
				partInfo info;
				info.pos = pAddress - image;
				memcpy(&info.partHex, (void*)pAddress, sizeof(info.partHex));
				vSearch.push_back(info);

				pAddress += 4;
				pAddress = (char*)FindBytes(pAddress, size - ((size_t)pAddress - (size_t)image), &feature2[i * 4], 4);
			}
		}

		char feature3[31 * 4] = {
		'\xE0','\x3B','\x00','\x32',  
		'\xE1','\x3B','\x00','\x32',  
		'\xE2','\x3B','\x00','\x32',  
		'\xE3','\x3B','\x00','\x32',  
		'\xE4','\x3B','\x00','\x32',  
		'\xE5','\x3B','\x00','\x32',  
		'\xE6','\x3B','\x00','\x32',  
		'\xE7','\x3B','\x00','\x32',  
		'\xE8','\x3B','\x00','\x32',  
		'\xE9','\x3B','\x00','\x32',  
		'\xEA','\x3B','\x00','\x32',  
		'\xEB','\x3B','\x00','\x32',  
		'\xEC','\x3B','\x00','\x32',  
		'\xED','\x3B','\x00','\x32',  
		'\xEE','\x3B','\x00','\x32',  
		'\xEF','\x3B','\x00','\x32',  
		'\xF0','\x3B','\x00','\x32',  
		'\xF1','\x3B','\x00','\x32',  
		'\xF2','\x3B','\x00','\x32',  
		'\xF3','\x3B','\x00','\x32',  
		'\xF4','\x3B','\x00','\x32',  
		'\xF5','\x3B','\x00','\x32',  
		'\xF6','\x3B','\x00','\x32',  
		'\xF7','\x3B','\x00','\x32',  
		'\xF8','\x3B','\x00','\x32',  
		'\xF9','\x3B','\x00','\x32',  
		'\xFA','\x3B','\x00','\x32',  
		'\xFB','\x3B','\x00','\x32',  
		'\xFC','\x3B','\x00','\x32',  
		'\xFD','\x3B','\x00','\x32',  
		'\xFE','\x3B','\x00','\x32',  
		};

		for (int i = 0; i < vSearch.size(); i++) {
			partInfo info = vSearch.at(i);
			for (int y = 0; y < 31; y++) {
				size_t findAddr = 0;
				if (memcmp((void*)((size_t)info.partHex + (size_t)4), &feature3[y * 4], 4) == 0) {
					findAddr = info.pos;
				} else if (memcmp((void*)((size_t)info.partHex + (size_t)8), &feature3[y * 4], 4) == 0) {
					findAddr = info.pos;
				} else if (memcmp((void*)((size_t)info.partHex + (size_t)12), &feature3[y * 4], 4) == 0) {
					findAddr = info.pos;
				}
				if (findAddr) {
					vSearchTotal.push_back(info);
					break;
				}
			}
		}
	}


	{
		char feature1[31 * 4] = {
			'\x00','\x00','\x90','\x52',  
			'\x01','\x00','\x90','\x52',  
			'\x02','\x00','\x90','\x52',  
			'\x03','\x00','\x90','\x52',  
			'\x04','\x00','\x90','\x52',  
			'\x05','\x00','\x90','\x52',  
			'\x06','\x00','\x90','\x52',  
			'\x07','\x00','\x90','\x52',  
			'\x08','\x00','\x90','\x52',  
			'\x09','\x00','\x90','\x52',  
			'\x0A','\x00','\x90','\x52',  
			'\x0B','\x00','\x90','\x52',  
			'\x0C','\x00','\x90','\x52',  
			'\x0D','\x00','\x90','\x52',  
			'\x0E','\x00','\x90','\x52',  
			'\x0F','\x00','\x90','\x52',  
			'\x10','\x00','\x90','\x52',  
			'\x11','\x00','\x90','\x52',  
			'\x12','\x00','\x90','\x52',  
			'\x13','\x00','\x90','\x52',  
			'\x14','\x00','\x90','\x52',  
			'\x15','\x00','\x90','\x52',  
			'\x16','\x00','\x90','\x52',  
			'\x17','\x00','\x90','\x52',  
			'\x18','\x00','\x90','\x52',  
			'\x19','\x00','\x90','\x52',  
			'\x1A','\x00','\x90','\x52',  
			'\x1B','\x00','\x90','\x52',  
			'\x1C','\x00','\x90','\x52',  
			'\x1D','\x00','\x90','\x52',  
			'\x1E','\x00','\x90','\x52',  
		};
		char feature2[31 * 4] = {
			'\xE0','\xFF','\x8F','\x12',  
			'\xE1','\xFF','\x8F','\x12',  
			'\xE2','\xFF','\x8F','\x12',  
			'\xE3','\xFF','\x8F','\x12',  
			'\xE4','\xFF','\x8F','\x12',  
			'\xE5','\xFF','\x8F','\x12',  
			'\xE6','\xFF','\x8F','\x12',  
			'\xE7','\xFF','\x8F','\x12',  
			'\xE8','\xFF','\x8F','\x12',  
			'\xE9','\xFF','\x8F','\x12',  
			'\xEA','\xFF','\x8F','\x12',  
			'\xEB','\xFF','\x8F','\x12',  
			'\xEC','\xFF','\x8F','\x12',  
			'\xED','\xFF','\x8F','\x12',  
			'\xEE','\xFF','\x8F','\x12',  
			'\xEF','\xFF','\x8F','\x12',  
			'\xF0','\xFF','\x8F','\x12',  
			'\xF1','\xFF','\x8F','\x12',  
			'\xF2','\xFF','\x8F','\x12',  
			'\xF3','\xFF','\x8F','\x12',  
			'\xF4','\xFF','\x8F','\x12',  
			'\xF5','\xFF','\x8F','\x12',  
			'\xF6','\xFF','\x8F','\x12',  
			'\xF7','\xFF','\x8F','\x12',  
			'\xF8','\xFF','\x8F','\x12',  
			'\xF9','\xFF','\x8F','\x12',  
			'\xFA','\xFF','\x8F','\x12',  
			'\xFB','\xFF','\x8F','\x12',  
			'\xFC','\xFF','\x8F','\x12',  
			'\xFD','\xFF','\x8F','\x12',  
			'\xFE','\xFF','\x8F','\x12',  
		};
		std::vector<partInfo> vSearch;

		for (int i = 0; i < 31; i++) {
			char* pAddress = (char*)FindBytes(image, size, &feature1[i * 4], 4);
			while (pAddress) {
				if ((size - (size_t)pAddress - (size_t)image) < 16) {
					break;
				}
				partInfo info;
				info.pos = pAddress - image;
				memcpy(&info.partHex, (void*)pAddress, sizeof(info.partHex));
				vSearch.push_back(info);

				pAddress += 4;
				pAddress = (char*)FindBytes(pAddress, size - ((size_t)pAddress - (size_t)image), &feature1[i * 4], 4);
			}
		}
		for (int i = 0; i < 31; i++) {
			char* pAddress = (char*)FindBytes(image, size, &feature2[i * 4], 4);
			while (pAddress) {

				if ((size - (size_t)pAddress - (size_t)image) < 16) {
					break;
				}
				partInfo info;
				info.pos = pAddress - image;
				memcpy(&info.partHex, (void*)pAddress, sizeof(info.partHex));
				vSearch.push_back(info);

				pAddress += 4;
				pAddress = (char*)FindBytes(pAddress, size - ((size_t)pAddress - (size_t)image), &feature2[i * 4], 4);
			}
		}


		char feature3[31 * 4] = {
		'\xE0','\xFF','\x8F','\x52',  
		'\xE1','\xFF','\x8F','\x52',  
		'\xE2','\xFF','\x8F','\x52',  
		'\xE3','\xFF','\x8F','\x52',  
		'\xE4','\xFF','\x8F','\x52',  
		'\xE5','\xFF','\x8F','\x52',  
		'\xE6','\xFF','\x8F','\x52',  
		'\xE7','\xFF','\x8F','\x52',  
		'\xE8','\xFF','\x8F','\x52',  
		'\xE9','\xFF','\x8F','\x52',  
		'\xEA','\xFF','\x8F','\x52',  
		'\xEB','\xFF','\x8F','\x52',  
		'\xEC','\xFF','\x8F','\x52',  
		'\xED','\xFF','\x8F','\x52',  
		'\xEE','\xFF','\x8F','\x52',  
		'\xEF','\xFF','\x8F','\x52',  
		'\xF0','\xFF','\x8F','\x52',  
		'\xF1','\xFF','\x8F','\x52',  
		'\xF2','\xFF','\x8F','\x52',  
		'\xF3','\xFF','\x8F','\x52',  
		'\xF4','\xFF','\x8F','\x52',  
		'\xF5','\xFF','\x8F','\x52',  
		'\xF6','\xFF','\x8F','\x52',  
		'\xF7','\xFF','\x8F','\x52',  
		'\xF8','\xFF','\x8F','\x52',  
		'\xF9','\xFF','\x8F','\x52',  
		'\xFA','\xFF','\x8F','\x52',  
		'\xFB','\xFF','\x8F','\x52',  
		'\xFC','\xFF','\x8F','\x52',  
		'\xFD','\xFF','\x8F','\x52',  
		'\xFE','\xFF','\x8F','\x52',  
		};

		for (int i = 0; i < vSearch.size(); i++) {
			partInfo info = vSearch.at(i);
			for (int y = 0; y < 31; y++) {
				size_t findAddr = 0;
				if (memcmp((void*)((size_t)info.partHex + (size_t)4), &feature3[y * 4], 4) == 0) {
					findAddr = info.pos;
				} else if (memcmp((void*)((size_t)info.partHex + (size_t)8), &feature3[y * 4], 4) == 0) {
					findAddr = info.pos;
				} else if (memcmp((void*)((size_t)info.partHex + (size_t)12), &feature3[y * 4], 4) == 0) {
					findAddr = info.pos;
				}
				if (findAddr) {

					vSearchTotal.push_back(info);
					break;
				}
			}
		}
	}

	RemoveDuplicatePartInfo(vSearchTotal);
	std::map<size_t, std::shared_ptr<size_t>> result_map;
	for (size_t i = 0; i < vSearchTotal.size(); i++) {
		result_map[vSearchTotal[i].pos] = std::make_shared<size_t>();
	}
	find_func_haed_link(image, size, result_map);
	RemoveDuplicateFuncStartResultMap(result_map);
	printf_head_result_map(result_map);
}

void SearchFeature3(const char* image, size_t image_size) {

	char feature_text_modulelayout[] = {
		'm', 'o', 'd', 'u', 'l', 'e', '_', 'l', 'a', 'y', 'o', 'u', 't', '\0',
	};
	char feature_text_disagrees_about_version_of_symbol[] = {
		'd', 'i', 's', 'a', 'g', 'r', 'e', 'e', 's', ' ', 'a', 'b', 'o', 'u', 't', ' ',  'v', 'e', 'r', 's', 'i', 'o', 'n', ' ', 'o', 'f', ' ', 's', 'y', 'm', 'b', 'o', 'l'
	};
	size_t modulelayout_text_offset = 0;

	for (size_t offset = 0; offset < image_size; offset++) {
		const char* paddr = image + offset;
		if ((image_size - offset) >= sizeof(feature_text_modulelayout)) {
			if (modulelayout_text_offset == 0 && memcmp(paddr, &feature_text_modulelayout, sizeof(feature_text_modulelayout)) == 0) {
				printf("module layout text addr->0x%p\n", (void*)offset);
				modulelayout_text_offset = offset;
			}
		}
		if (modulelayout_text_offset) {
			break;
		}
	}

	for (size_t offset = 0; offset < image_size; offset++) {
		const char* paddr = image + offset;
		if ((image_size - offset) >= sizeof(feature_text_disagrees_about_version_of_symbol)) {
			if (memcmp(paddr, &feature_text_disagrees_about_version_of_symbol, sizeof(feature_text_disagrees_about_version_of_symbol)) == 0) {
				printf("disagrees_about_version_of_symbol text addr->0x%p\n", (void*)offset);
				break;
			}
		}
	}

	if (!modulelayout_text_offset) {
		printf("[ERROR] text offset empty.\n");
		return;
	}

	std::map<std::tuple<std::string, size_t>, std::shared_ptr<std::vector<xrefs_info>>> result_map;
	result_map[{"load_module function", modulelayout_text_offset}] = std::make_shared<std::vector<xrefs_info>>();
	find_xrefs_link((const char*)image, image_size, result_map);
	printf_xrefs_result_map(result_map);
}

void TestModuleSignature(char* image, size_t size) {
	const char* lpszFlag = "Module signature appended";
	const char* pAddress = FindBytes(image, size, lpszFlag, strlen(lpszFlag));
	if (pAddress != 0) {
		printf("该内核文件【有】签名Module signature appended样式\n");
	} else {
		printf("该内核文件【无】签名Module signature appended样式\n");
	}
}

int main(int argc, char* argv[]) {
	++argv;
	--argc;

	std::cout << "本工具用于查找在aarch64 Linux内核文件中load_module的位置" << std::endl;
	int nFileSize = 0;
	if (argc < 1) {
		std::cout << "无输入文件" << std::endl;
		system("pause");
		return 0;
	}


	char* image = GetFileBuf(argv[0], nFileSize);
#endif
	if (!image) {
		std::cout << "打开文件失败:" << argv[0] << std::endl;
		system("pause");
		return 0;
	}

	std::cout << "===============Engine1===============" << std::endl;
	SearchFeature1(image, nFileSize);
#ifdef _DEBUG
	std::cout << "按任意键开始使用下一个搜索引擎" << std::endl;
	system("pause");
#endif
	std::cout << "===============Engine2===============" << std::endl;
	SearchFeature2(image, nFileSize);

#ifdef _DEBUG
	std::cout << "按任意键开始使用下一个搜索引擎" << std::endl;
	system("pause");
#endif
	std::cout << "===============Engine3===============" << std::endl;
	SearchFeature3(image, nFileSize);

	TestModuleSignature(image, nFileSize);
	free(image);
	system("pause");
	return 0;

}
