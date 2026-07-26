// SPDX-FileCopyrightText: 2026 Paracelsus83
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "exe_file.hpp"
#include <cstdint>
#include <fstream>


namespace {

	template <uint32_t N>
	static constexpr uint64_t ToUInt64(const char(&str)[N]) {
		static_assert(N <= 8, "String too long to convert to uint64_t");
		uint64_t result = 0;
		for (uint32_t i = 0; i < N; ++i) {
			result |= static_cast<uint64_t>(str[i]) << (8 * i);
		}
		return result;
	}

	enum ESectionName : uint64_t {
		TEXT = ToUInt64(".text"),
		RDATA = ToUInt64(".rdata"),
		DATA = ToUInt64(".data"),
		RSRC = ToUInt64(".rsrc")
	};

	constexpr size_t MAX_EXE_SIZE = 8 * 1024 * 1024; // 8 MB

} // namespace


EXEFile::LoadResult EXEFile::Load(const std::string& path) {
	std::ifstream file(path, std::ios::ios_base::in | std::ios::binary | std::ios::ate);
	if (!file.is_open()) {
		return LoadResult::CANT_OPEN;
	}

	auto exeFileSize = file.tellg();
	if (exeFileSize < sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS32) || exeFileSize > MAX_EXE_SIZE) {
		return LoadResult::CORRUPTED;
	}

	fileSize = static_cast<std::size_t>(exeFileSize);
	buffer.reset(new char[fileSize]);
	codeSection = rDataSection = dataSection = rsrcSection = nullptr;

	file.seekg(0, std::ios::beg);
	file.read(buffer.get(), exeFileSize);
	if (file.fail() || file.gcount() != exeFileSize) {
		return LoadResult::READ_ERROR;
	}
	file.close();

	PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(buffer.get());
	if (   dosHeader->e_magic != IMAGE_DOS_SIGNATURE
		|| dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS32) > fileSize
	) {
		return LoadResult::CORRUPTED;
	}

	ntHeaders = Offset2Ptr<IMAGE_NT_HEADERS32>(dosHeader->e_lfanew);
	if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
		return LoadResult::CORRUPTED;
	}

	const WORD numOfSections = ntHeaders->FileHeader.NumberOfSections;
	PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
	for (int i = 0; i < numOfSections; ++i, ++sectionHeader) {
		if (sectionHeader->PointerToRawData + sectionHeader->SizeOfRawData > fileSize) {
			return LoadResult::CORRUPTED;
		}
		switch (reinterpret_cast<ESectionName&>(sectionHeader->Name)) {
		case ESectionName::TEXT:
			if (   sectionHeader->PointerToRawData != sectionHeader->VirtualAddress
				|| sectionHeader->Misc.VirtualSize > sectionHeader->SizeOfRawData) { return LoadResult::UNSUPPORTED; }
			codeSection = sectionHeader;
			break;
		case ESectionName::RDATA:
			if (   sectionHeader->PointerToRawData != sectionHeader->VirtualAddress
				|| sectionHeader->Misc.VirtualSize > sectionHeader->SizeOfRawData) { return LoadResult::UNSUPPORTED; }
			rDataSection = sectionHeader;
			break;
		case ESectionName::DATA:
			if (sectionHeader->PointerToRawData != sectionHeader->VirtualAddress) { return LoadResult::UNSUPPORTED; }
			dataSection = sectionHeader;
			break;
		case ESectionName::RSRC:
			if (sectionHeader->Misc.VirtualSize > sectionHeader->SizeOfRawData) { return LoadResult::UNSUPPORTED; }
			rsrcSection = sectionHeader;
			break;
		}
	}

	return (codeSection && rDataSection && dataSection && rsrcSection) ? LoadResult::OK : LoadResult::UNSUPPORTED;
}


ResourceParser EXEFile::GetResourceParser() {
	PIMAGE_DATA_DIRECTORY resourceDirectory = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];
	if (   resourceDirectory->VirtualAddress == 0
		|| resourceDirectory->Size == 0
		|| resourceDirectory->VirtualAddress != rsrcSection->VirtualAddress
		|| resourceDirectory->Size > rsrcSection->SizeOfRawData
	) {
		return ResourceParser();
	}
	else {
		BYTE* rsrcBase = Offset2Ptr<BYTE>(rsrcSection->PointerToRawData);
		return ResourceParser(
			rsrcBase,
			rsrcSection->SizeOfRawData,
			rsrcBase - rsrcSection->VirtualAddress
		);
	}
}


DWORD EXEFile::AddDllImport(std::string_view dllName, std::string_view funcName) {
	IMAGE_DATA_DIRECTORY& importDirectory = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

	if (   importDirectory.VirtualAddress == 0
		|| importDirectory.VirtualAddress < rDataSection->VirtualAddress
		|| importDirectory.Size == 0
		|| importDirectory.Size % sizeof(IMAGE_IMPORT_DESCRIPTOR) != 0
	) {
		return 0;
	}

	const DWORD offsetOfImportDirEnd = importDirectory.VirtualAddress + importDirectory.Size;
	DWORD offsetOfEoD = rDataSection->VirtualAddress + rDataSection->Misc.VirtualSize;

	if (offsetOfImportDirEnd > offsetOfEoD) {
		return 0;
	}

	auto* const importDescrEnd = Offset2Ptr<IMAGE_IMPORT_DESCRIPTOR>(offsetOfImportDirEnd);
	auto* const importDescrLast = importDescrEnd - 1;

	if (   importDescrLast->Characteristics != 0
		|| importDescrLast->Name != 0
		|| importDescrLast->FirstThunk != 0
	) {
		return 0;
	}

	PIMAGE_IMPORT_DESCRIPTOR importDescrToBeFix = nullptr;
	size_t sizeOfILTForMove = 0;

	for (
		auto* importDescr = Offset2Ptr<IMAGE_IMPORT_DESCRIPTOR>(importDirectory.VirtualAddress);
		importDescr < importDescrEnd;
		++importDescr
	) {
		if (importDescr->OriginalFirstThunk == offsetOfImportDirEnd) {
			// this ILT is located immediately after the import directory, so it must be moved to a free space
			importDescrToBeFix = importDescr;

			PDWORD pImpLookupTable = Offset2Ptr<DWORD>(offsetOfImportDirEnd);
			PDWORD pItem = pImpLookupTable;
			while (*pItem++ != 0);
			sizeOfILTForMove = (pItem - pImpLookupTable) * sizeof(DWORD);
			break;
		}
	}

	if (sizeOfILTForMove < sizeof(IMAGE_IMPORT_DESCRIPTOR)) {
		return 0;
	}

	if (buffer[offsetOfEoD - 1] != 0) {
		buffer[offsetOfEoD++] = 0; // string termination
	}
	if (offsetOfEoD & 1) {
		++offsetOfEoD; // align 2 bytes
	}

	// prepare new import descriptor
	importDescrLast->TimeDateStamp = 0;
	importDescrLast->ForwarderChain = 0;

	const DWORD funcHintNameRVA = offsetOfEoD;

	// write hint for the imported function
	Offset2Ref<WORD>(offsetOfEoD) = 0;
	offsetOfEoD += sizeof(WORD);

	// write name of the imported function
	memcpy(&buffer[offsetOfEoD], funcName.data(), funcName.size());
	offsetOfEoD += funcName.size();
	buffer[offsetOfEoD++] = 0; // string termination

	// write name of the imported DLL
	importDescrLast->Name = offsetOfEoD;
	memcpy(&buffer[offsetOfEoD], dllName.data(), dllName.size());
	offsetOfEoD += dllName.size();
	buffer[offsetOfEoD++] = 0; // string termination

	// alignment for ILT
	if (offsetOfEoD & 3) {
		offsetOfEoD |= 3; // align 4 bytes
		++offsetOfEoD;
	}

	// move ILT for importDescrToBeFix
	memcpy(&buffer[offsetOfEoD], importDescrEnd, sizeOfILTForMove);
	importDescrToBeFix->OriginalFirstThunk = offsetOfEoD;
	offsetOfEoD += sizeOfILTForMove;

	// clear the original ILT location so that it becomes the import directory terminator
	memset(importDescrEnd, 0, sizeOfILTForMove);

	// write ILT entry for the imported function
	importDescrLast->OriginalFirstThunk = offsetOfEoD;
	Offset2Ref<DWORD>(offsetOfEoD) = funcHintNameRVA;
	offsetOfEoD += sizeof(DWORD);
	Offset2Ref<DWORD>(offsetOfEoD) = 0;
	offsetOfEoD += sizeof(DWORD);

	// write IAT entry for the imported function
	importDescrLast->FirstThunk = offsetOfEoD;
	Offset2Ref<DWORD>(offsetOfEoD) = funcHintNameRVA;
	offsetOfEoD += sizeof(DWORD);
	Offset2Ref<DWORD>(offsetOfEoD) = 0;
	offsetOfEoD += sizeof(DWORD);

	rDataSection->Misc.VirtualSize = offsetOfEoD - rDataSection->VirtualAddress;
	if (rDataSection->Misc.VirtualSize > rDataSection->SizeOfRawData) {
		return 0;
	}

	importDirectory.Size += sizeof(IMAGE_IMPORT_DESCRIPTOR);

	return ntHeaders->OptionalHeader.ImageBase + importDescrLast->FirstThunk;
}


bool EXEFile::Save(const std::string& path) {
	try {
		std::ofstream file(path, std::ios::binary | std::ios::trunc);
		if (!file.is_open()) {
			return false;
		}
		file.write(buffer.get(), fileSize);
	}
	catch (...) {
		return false;
	}

	return true;
}
