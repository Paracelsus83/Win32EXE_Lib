// SPDX-FileCopyrightText: 2026 Paracelsus83
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "exe_file.hpp"
#ifdef _MSC_VER
#include <verrsrc.h>
#else
#include <winver.h>
#endif


namespace {

	enum ResourceType : WORD {
		R_CURSOR = 1,
		R_BITMAP = 2,
		R_ICON = 3,
		R_MENU = 4,
		R_DIALOG = 5,
		R_STRING = 6,
		R_FONTDIR = 7,
		R_FONT = 8,
		R_ACCELERATOR = 9,
		R_RCDATA = 10,
		R_MESSAGETABLE = 11,
		R_GROUP_CURSOR = 12,
		R_GROUP_ICON = 14,
		R_VERSION = 16,
		R_DLGINCLUDE = 17,
		R_MANIFEST = 24
	};

	struct ResourceHeader {
		WORD  wLength;
		WORD  wValueLength;
		WORD  wType;
	};

	struct Resource : public ResourceHeader {
		WCHAR strings[1];
	};

	struct MsvcVersionInfo {
		MsvcVersionInfo() = delete;

		ResourceHeader rVerInfoHead;
		WCHAR verInfoKey[16]; // text "VS_VERSION_INFO"
		[[maybe_unused]] WORD _padding;
		VS_FIXEDFILEINFO fileInfo;
		ResourceHeader rStrFileInfoHead;
		WCHAR strFileInfoKey[15];
		ResourceHeader rLangHead;
		[[maybe_unused]] WCHAR langKey[9];
	};

	template <size_t N>
	inline bool WStrNotEqual(const WCHAR(&lhs)[N], const WCHAR(&rhs)[N]) {
		return memcmp(lhs, rhs, N * sizeof(WCHAR)) != 0;
	}

} // namespace


struct ResourceNode {
	IMAGE_RESOURCE_DIRECTORY Dir;
	IMAGE_RESOURCE_DIRECTORY_ENTRY Entries[6];
};


ResourceParser::ResourceParser(BYTE* base, DWORD size, BYTE* vBase) :
	rsrcBase(base), rsrcEnd(base + size), resVirtBase(vBase)
{
	const ResourceNode& typesNode = *reinterpret_cast<ResourceNode*>(rsrcBase);

	auto* pTypeIdEntry = &typesNode.Entries[typesNode.Dir.NumberOfNamedEntries];
	const auto* const endOfEntries = pTypeIdEntry + typesNode.Dir.NumberOfIdEntries;

	for (; pTypeIdEntry < endOfEntries; ++pTypeIdEntry) {

		if (!pTypeIdEntry->DataIsDirectory) continue;

		auto* pNamesNode = reinterpret_cast<ResourceNode*>(rsrcBase + pTypeIdEntry->OffsetToDirectory);

		switch (pTypeIdEntry->Name) {
			case ResourceType::R_ICON:
				pIconsNode = pNamesNode;
				break;
			case ResourceType::R_VERSION:
				pVersionNode = pNamesNode;
				break;
		}
	}
}


bool ResourceParser::UpdateVersion(VSVersion fileVer, VSVersion prodVer, const WStringMap& stringMap) {

	auto* pNameNode = pVersionNode;
	const DWORD totalNames = pNameNode->Dir.NumberOfNamedEntries + pNameNode->Dir.NumberOfIdEntries;

	for (DWORD j = pNameNode->Dir.NumberOfNamedEntries; j < totalNames; ++j) {
		if (!pNameNode->Entries[j].DataIsDirectory) continue;

		BYTE* pLangDirPtr = rsrcBase + pNameNode->Entries[j].OffsetToDirectory;
		auto* pLangNode = reinterpret_cast<ResourceNode*>(pLangDirPtr);

		if (pLangNode->Entries[0].DataIsDirectory) continue; // Liść nie może być katalogiem

		BYTE* pDataEntryPtr = rsrcBase + pLangNode->Entries[0].OffsetToData;
		auto* pDataEntry = reinterpret_cast<PIMAGE_RESOURCE_DATA_ENTRY>(pDataEntryPtr);

		auto* pVersionInfo = reinterpret_cast<MsvcVersionInfo*>(resVirtBase + pDataEntry->OffsetToData);

		if (   pVersionInfo->rVerInfoHead.wValueLength != sizeof(VS_FIXEDFILEINFO)
			|| WStrNotEqual(pVersionInfo->verInfoKey, L"VS_VERSION_INFO")
			|| pVersionInfo->fileInfo.dwSignature != VS_FFI_SIGNATURE
			|| pVersionInfo->fileInfo.dwStrucVersion != VS_FFI_STRUCVERSION
			|| pVersionInfo->rStrFileInfoHead.wValueLength != 0
			|| WStrNotEqual(pVersionInfo->strFileInfoKey, L"StringFileInfo")
			|| pVersionInfo->rLangHead.wValueLength != 0
		) {
			continue;
		}

		if (fileVer) {
			pVersionInfo->fileInfo.dwFileVersionMS = fileVer.msw;
			pVersionInfo->fileInfo.dwFileVersionLS = fileVer.lsw;
		}
		if (prodVer) {
			pVersionInfo->fileInfo.dwProductVersionMS = prodVer.msw;
			pVersionInfo->fileInfo.dwProductVersionLS = prodVer.lsw;
		}

		const void* const endPtr = reinterpret_cast<BYTE*>(pVersionInfo) + pVersionInfo->rVerInfoHead.wLength;

		for (
			auto* readPtr = reinterpret_cast<Resource*>(pVersionInfo + 1);
			readPtr < endPtr;
			reinterpret_cast<uintptr_t&>(readPtr) += readPtr->wLength
		) {
			if (readPtr->wType == 1) {
				const std::wstring_view key(readPtr->strings);
				if (auto it = stringMap.find(key); it != stringMap.end()) {
					const auto& value = it->second;
					if ((value.size()+1) * 2 == readPtr->wValueLength) {
						PWCHAR pDestValue = readPtr->strings + key.size() + (key.size() & 1) + 1;
						value.copy(pDestValue, value.size());
					}
				}
			}
		}
		return true;
	}

	return false;
}
