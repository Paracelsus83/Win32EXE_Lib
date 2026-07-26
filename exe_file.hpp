// SPDX-FileCopyrightText: 2026 Paracelsus83
// SPDX-License-Identifier: LGPL-3.0-or-later

#pragma once

#include <cstring>
#include <map>
#include <memory>
#include <string>
#include "min_win.hpp"


namespace Asm {
	template <class... Instructions> class Sequence;
}

struct ResourceNode;

struct VSVersion {
	DWORD msw;
	DWORD lsw;

	constexpr VSVersion() : msw(0), lsw(0) {}
	constexpr VSVersion(WORD v1, WORD v2, WORD v3, WORD v4) : msw((v1 << 16) | v2), lsw((v3 << 16) | v4) {}

	explicit constexpr operator bool() const { return msw || lsw; }
};

using WStringMap = std::map<std::wstring_view, std::wstring_view>;

class ResourceParser {
	friend class EXEFile;

	BYTE* rsrcBase = nullptr;
	const void* rsrcEnd = nullptr;
	BYTE* resVirtBase = nullptr;

	ResourceNode* pIconsNode = nullptr;
	ResourceNode* pVersionNode = nullptr;

	ResourceParser() = default;
	ResourceParser(BYTE* base, DWORD size, BYTE* vBase);

public:
	explicit operator bool() { return rsrcBase != nullptr; }
	bool UpdateVersion(VSVersion fileVer, VSVersion prodVer, const WStringMap& stringMap);
};


class EXEFile {
public:
	enum class LoadResult {
		OK = 0,
		CANT_OPEN,
		READ_ERROR,
		CORRUPTED,
		UNSUPPORTED
	};

	LoadResult Load(const std::string& path);
	bool Save(const std::string& path);

	ResourceParser GetResourceParser();
	DWORD AddDllImport(std::string_view dllName, std::string_view funcName);

	void SetImageVersion(WORD major, WORD minor) {
		ntHeaders->OptionalHeader.MajorImageVersion = major;
		ntHeaders->OptionalHeader.MinorImageVersion = minor;
	}

	template<class T>
	void Patch(DWORD addr, const T& data) {
		std::memcpy(Address2Ptr(addr), &data, sizeof(data));
	}

	template<class... I>
	void PatchCodeAsm(DWORD addr, const Asm::Sequence<I...>& seq) {
		reinterpret_cast<Asm::Sequence<I...>*>(
			std::memcpy(Address2Ptr(addr), &seq, sizeof(seq))
		)->UpdateAddr(addr);
	}

private:
	std::unique_ptr<char[]> buffer;
	std::size_t fileSize = 0;

	PIMAGE_NT_HEADERS32 ntHeaders;

	PIMAGE_SECTION_HEADER codeSection;
	PIMAGE_SECTION_HEADER rDataSection;
	PIMAGE_SECTION_HEADER dataSection;
	PIMAGE_SECTION_HEADER rsrcSection;

	template <class T = void>
	T* Offset2Ptr(DWORD offset) {
		return reinterpret_cast<T*>(buffer.get() + offset);
	}

	template <class T>
	T& Offset2Ref(DWORD offset) {
		return *Offset2Ptr<T>(offset);
	}

	template <class T = void>
	T* Address2Ptr(DWORD addr) {
		return Offset2Ptr<T>(addr - ntHeaders->OptionalHeader.ImageBase);
	}
};
