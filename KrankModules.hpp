#ifndef _KRANK_MODULES_
#define _KRANK_MODULES_

#pragma once

namespace KRANK
{
	namespace DEFINITION
	{
		struct UNICODE_STRING
		{
			unsigned short		Length;
			unsigned short		MaximumLength;
			wchar_t*			Buffer;
		};

		struct IMAGE_DOS_HEADER
		{
			unsigned short		e_magic;
			unsigned short		e_cblp;
			unsigned short		e_cp;
			unsigned short		e_crlc;
			unsigned short		e_cparhdr;
			unsigned short		e_minalloc;
			unsigned short		e_maxalloc;
			unsigned short		e_ss;
			unsigned short		e_sp;
			unsigned short		e_csum;
			unsigned short		e_ip;
			unsigned short		e_cs;
			unsigned short		e_lfarlc;
			unsigned short		e_ovno;
			unsigned short		e_res[4];
			unsigned short		e_oemid;
			unsigned short		e_oeminfo;
			unsigned short		e_res2[10];
			long				e_lfanew;
		};

		struct IMAGE_DATA_DIRECTORY
		{
			unsigned int	VirtualAddress;
			unsigned int	Size;
		};

		struct IMAGE_OPTIONAL_HEADER
		{
			unsigned short			Magic;
			unsigned char			MajorLinkerVersion;
			unsigned char			MinorLinkerVersion;
			unsigned int			SizeOfCode;
			unsigned int			SizeOfInitializedData;
			unsigned int			SizeOfUninitializedData;
			unsigned int			AddressOfEntryPoint;
			unsigned int			BaseOfCode;
			unsigned int			BaseOfData;
			unsigned int			ImageBase;
			unsigned int			SectionAlignment;
			unsigned int			FileAlignment;
			unsigned short			MajorOperatingSystemVersion;
			unsigned short			MinorOperatingSystemVersion;
			unsigned short			MajorImageVersion;
			unsigned short			MinorImageVersion;
			unsigned short			MajorSubsystemVersion;
			unsigned short			MinorSubsystemVersion;
			unsigned int			Win32VersionValue;
			unsigned int			SizeOfImage;
			unsigned int			SizeOfHeaders;
			unsigned int			CheckSum;
			unsigned short			Subsystem;
			unsigned short			DllCharacteristics;
			unsigned int			SizeOfStackReserve;
			unsigned int			SizeOfStackCommit;
			unsigned int			SizeOfHeapReserve;
			unsigned int			SizeOfHeapCommit;
			unsigned int			LoaderFlags;
			unsigned int			NumberOfRvaAndSizes;
			IMAGE_DATA_DIRECTORY	DataDirectory[16];
		};

		struct IMAGE_FILE_HEADER
		{
			unsigned short		 Machine;
			unsigned short		NumberOfSections;
			unsigned int		TimeDateStamp;
			unsigned int		PointerToSymbolTable;
			unsigned int		NumberOfSymbols;
			unsigned short		SizeOfOptionalHeader;
			unsigned short		Characteristics;
		};

		struct IMAGE_NT_HEADERS
		{
			unsigned int			Signature;
			IMAGE_FILE_HEADER		FileHeader;
			IMAGE_OPTIONAL_HEADER	OptionalHeader;
		};

		struct IMAGE_EXPORT_DIRECTORY
		{
			unsigned int		Characteristics;
			unsigned int		TimeDateStamp;
			unsigned short		MajorVersion;
			unsigned short		MinorVersion;
			unsigned int		Name;
			unsigned int		Base;
			unsigned int		NumberOfFunctions;
			unsigned int		NumberOfNames;
			unsigned int		AddressOfFunctions;
			unsigned int		AddressOfNames;
			unsigned int		AddressOfNameOrdinals;
		};

		struct LIST_ENTRY
		{
			LIST_ENTRY *	Flink;
			LIST_ENTRY *	Blink;
		};

		struct PEB_LDR_DATA
		{
			unsigned long		Length;
			unsigned char		Initialized;
			void *				SsHandle;
			LIST_ENTRY			InLoadOrderModuleList;
			LIST_ENTRY			InMemoryOrderModuleList;
			LIST_ENTRY			InInitializationOrderModuleList;
			void *				EntryInProgress;
			unsigned char		ShutdownInProgress;
			void *				ShutdownThreadId;
		};

		struct PEB
		{
			unsigned char	InheritedAddressSpace;
			unsigned char	ReadImageFileExecOptions;
			unsigned char	BeingDebugged;

			union
			{
				unsigned char BitField;

				struct
				{
					unsigned char ImageUsedLargePages			: 1;
					unsigned char IsProtectedProcess			: 1;
					unsigned char IsLegacyProcess				: 1;
					unsigned char IsImageDynamicallyRelocated	: 1;
					unsigned char SkipPatchingUser32Forwarders	: 1;
					unsigned char IsPackagedProcess				: 1;
					unsigned char IsAppContainer				: 1;
					unsigned char IsProtectedProcessLight		: 1;
					unsigned char IsLongPathAwareProcess		: 1;
					unsigned char SpareBits						: 4;
				};
			};

			void *			Mutant;
			void *			ImageBaseAddress;
			PEB_LDR_DATA*	Ldr;
		};

		struct LDR_DATA_TABLE_ENTRY
		{
			LIST_ENTRY			InLoadOrderLinks;
			LIST_ENTRY			InMemoryOrderLinks;
			LIST_ENTRY			InInitializationOrderLinks;
			void *				DllBase;
			void *				EntryPoint;
			unsigned long		SizeOfImage;
			UNICODE_STRING		FullDllName;
			UNICODE_STRING		BaseDllName;
			unsigned long		Flags;
			unsigned short		LoadCount;
			unsigned short		TlsIndex;
		};

		struct MEMORY_BASIC_INFORMATION
		{
			void *			BaseAddress;
			void *			AllocationBase;
			unsigned int	AllocationProtect;
			unsigned long	RegionSize;
			unsigned int	State;
			unsigned int	Protect;
			unsigned int	Type;
		};

		enum MEMORY_INFORMATION_CLASS
		{
			MemoryBasicInformation,
			MemoryWorkingSetInformation,
			MemoryMappedFilenameInformation,
			MemoryRegionInformation,
			MemoryWorkingSetExInformation,
			MemorySharedCommitInformation,
			MemoryImageInformation,
			MemoryRegionInformationEx,
			MemoryPrivilegedBasicInformation,
			MemoryEnclaveImageInformation,
			MemoryBasicInformationCapped
		};

		struct SECTION_INFO
		{
			unsigned short		Length;
			unsigned short		MaximumLength;
			wchar_t *			DataBuffer;
			unsigned char		Data[256 * 2];
		};
	}

	namespace TEXT
	{
		auto __forceinline KrankToLowercaseA(
			char Character
		) -> char
		{
			if (
				Character <= 'Z' 
				&& Character >= 'A'
				) 
			{
				return Character - ('Z' - 'z');
			}

			return Character;
		}

		auto __forceinline KrankToUppercaseA(
			char Character
		) -> char
		{
			if (
				Character <= 'z' 
				&& Character >= 'a'
				)
			{
				return Character - ('z' - 'Z');
			}

			return Character;
		}

		auto __forceinline KrankToLowercaseW(
			wchar_t Character
		) -> wchar_t
		{
			if (
				Character <= 'Z' 
				&& Character >= 'A'
				) 
			{
				return Character - ('Z' - 'z');
			}

			return Character;
		}

		auto __forceinline KrankToUppercaseW(
			wchar_t Character
		) -> wchar_t
		{
			if (
				Character <= 'z' 
				&& Character >= 'a'
				)
			{
				return Character - ('z' - 'Z');
			}
			return Character;
		}

		auto KrankTextSizeA(
			const char * Text
		) -> int
		{
			int Size = 0;

			while(Text[Size] != '\0')
			{
				++Size;
			}

			return Size;
		}

		auto KrankTextSizeW(
			const wchar_t * Text
		) -> int
		{
			int Size = 0;

			while(Text[Size] != '\0')
			{
				++Size;
			}

			return Size;
		}

		auto KrankCopyTextA(
			char *			Text1,
			const char *	Text2,
			int				Size
		) -> void
		{
			for(int i = 0; i < Size; ++i)
			{
				Text1[i] = Text2[i];
			}

			Text1[Size] = '\0';

			return;
		}

		auto KrankCopyTextW(
			wchar_t *		Text1,
			const wchar_t *	Text2,
			int				Size
		) -> void
		{
			for(int i = 0; i < Size; ++i)
			{
				Text1[i] = Text2[i];
			}

			Text1[Size] = '\0';

			return;
		}

		auto KrankCompareTextA(
			const char *	Text1,
			const char *	Text2,
			bool			CaseSensitive = true
		) -> bool 
		{
			int Index = 0;

			int Text1Size = KrankTextSizeA(Text1);
			int Text2Size = KrankTextSizeA(Text2);

			if(Text1Size == Text2Size)
			{
				while(
					true == CaseSensitive 
					? Text1[Index] == Text2[Index]
					: KrankToLowercaseA(Text1[Index]) == KrankToLowercaseA(Text2[Index])
					&& Text1[Index] != '\0'
					&& Text2[Index] != '\0')
				{
					++Index;
				}
				if(KrankToLowercaseA(Text1[Index]) == KrankToLowercaseA(Text2[Index]))
				{
					return true;
				}
			}

			return false;
		}

		auto KrankCompareTextW(
			const wchar_t *	Text1,
			const wchar_t *	Text2,
			bool			CaseSensitive = true
		) -> bool 
		{
			int Index = 0;

			int Text1Size = KrankTextSizeW(Text1);
			int Text2Size = KrankTextSizeW(Text2);

			if(Text1Size == Text2Size)
			{
				while(
					true == CaseSensitive 
					? Text1[Index] == Text2[Index]
					: KrankToLowercaseW(Text1[Index]) == KrankToLowercaseW(Text2[Index])
					&& Text1[Index] != '\0'
					&& Text2[Index] != '\0')
				{
					++Index;
				}
				if(KrankToLowercaseW(Text1[Index]) == KrankToLowercaseW(Text2[Index]))
				{
					return true;
				}
			}

			return false;
		}
	}

	namespace MODULE
	{
		struct KRANK_MODULE_INFORMATION
		{
			wchar_t*			Name;
			unsigned long		BaseAddress;
			unsigned int		Size;
		};

		enum KRANK_MODULE_LIST_ORDER : unsigned int
		{
			KRANK_MODULE_LIST_LOAD_ORDER = 0,
			KRANK_MODULE_LIST_MEMORY_ORDER,
			KRANK_MODULE_LIST_INITIALIZATION_ORDER 
		};

		auto KrankGetModuleListByOrder(
			KRANK_MODULE_LIST_ORDER ListOrder
		) -> unsigned long
		{
			unsigned long ModuleListAddress = 0;

			__asm
			{
				mov eax, fs:[0x30];
				mov eax, [eax + 0xC];

				mov edx, ListOrder;

				mov ebx, 0;
				cmp edx, ebx;
				je LoadOrder;

				mov ebx, 1;
				cmp edx, ebx;
				je MemoryOrder;

				mov ebx, 2;
				cmp edx, ebx;
				je InitializationOrder;

				jmp ReturnAddress;

			LoadOrder:
				mov eax, [eax + 0xC];
				jmp ReturnAddress;

			MemoryOrder:
				mov eax, [eax + 0x14];
				jmp ReturnAddress;

			InitializationOrder:
				mov eax, [eax + 0x1C];
				jmp ReturnAddress;

			ReturnAddress:
				mov ModuleListAddress, eax;
			}

			return ModuleListAddress;
		}

		auto KrankGetModule(
			const wchar_t *				ModuleName,
			KRANK_MODULE_LIST_ORDER		ListOrder = KRANK_MODULE_LIST_LOAD_ORDER
		) -> KRANK_MODULE_INFORMATION
		{
			KRANK::DEFINITION::LDR_DATA_TABLE_ENTRY * Modules = reinterpret_cast<decltype(Modules)>
				(KrankGetModuleListByOrder(ListOrder));

			KRANK_MODULE_INFORMATION ModuleInformation = decltype(ModuleInformation){};

			while(
				nullptr != Modules
				&& Modules->DllBase
				)
			{
				if(true == KRANK::TEXT::KrankCompareTextW(
					ModuleName,
					Modules->BaseDllName.Buffer,
					false
				))
				{
					ModuleInformation.Name			= Modules->BaseDllName.Buffer;
					ModuleInformation.BaseAddress	= reinterpret_cast
													<decltype(ModuleInformation.BaseAddress)>
													(Modules->DllBase);
					ModuleInformation.Size			= Modules->SizeOfImage;

					return ModuleInformation;
				}

				switch(ListOrder)
				{
				case(KRANK_MODULE_LIST_LOAD_ORDER):
				{
					Modules = reinterpret_cast<decltype(Modules)>(Modules->InLoadOrderLinks.Flink);
					break;
				}
				case(KRANK_MODULE_LIST_MEMORY_ORDER):
				{
					Modules = reinterpret_cast<decltype(Modules)>(Modules->InMemoryOrderLinks.Flink);
					break;
				}
				case(KRANK_MODULE_LIST_INITIALIZATION_ORDER):
				{
					Modules = reinterpret_cast<decltype(Modules)>(Modules->InInitializationOrderLinks.Flink);
					break;
				}
				}
			}

			return ModuleInformation;
		}

		auto KrankGetFunction(
			KRANK_MODULE_INFORMATION *		ModuleInformation,
			const char *					Function
		) -> unsigned long
		{
			KRANK::DEFINITION::IMAGE_DOS_HEADER * Dos			= reinterpret_cast<decltype(Dos)>
				(ModuleInformation->BaseAddress);
			KRANK::DEFINITION::IMAGE_NT_HEADERS * Nt			= nullptr;
			KRANK::DEFINITION::IMAGE_EXPORT_DIRECTORY * Export	= nullptr;

			if(nullptr != Dos)
			{
				Nt = reinterpret_cast<decltype(Nt)>(ModuleInformation->BaseAddress + Dos->e_lfanew);

				if(nullptr != Nt)
				{
					Export = reinterpret_cast<decltype(Export)>(ModuleInformation->BaseAddress 
						+ Nt->OptionalHeader.DataDirectory[0].VirtualAddress);

					if(nullptr != Export)
					{
						unsigned int * FunctionAddresses = reinterpret_cast<decltype(FunctionAddresses)>
							(ModuleInformation->BaseAddress + Export->AddressOfFunctions);

						if(nullptr != FunctionAddresses)
						{
							unsigned int * FunctionNames = reinterpret_cast<decltype(FunctionNames)>
								(ModuleInformation->BaseAddress + Export->AddressOfNames);

							if(nullptr != FunctionNames)
							{
								unsigned short * FunctionOrdinals = reinterpret_cast<decltype(FunctionOrdinals)>
									(ModuleInformation->BaseAddress + Export->AddressOfNameOrdinals);

								if(nullptr != FunctionOrdinals)
								{
									for(int i = 0; i < Export->NumberOfFunctions; ++i)
									{
										if(KRANK::TEXT::KrankCompareTextA(
											Function,
											reinterpret_cast<char*>(ModuleInformation->BaseAddress 
												+ FunctionNames[i]),
											false
										))
										{
											return (ModuleInformation->BaseAddress 
												+ FunctionAddresses[FunctionOrdinals[i]]);
										}
									}
								}
							}
						}
					}
				}
			}

			return 0;
		}

		auto KrankHideModulePeb(
			KRANK_MODULE_INFORMATION *		ModuleInformation,
			KRANK_MODULE_LIST_ORDER			ListOrder = KRANK_MODULE_LIST_LOAD_ORDER
		) -> bool
		{
			KRANK::DEFINITION::LDR_DATA_TABLE_ENTRY * Modules = reinterpret_cast<decltype(Modules)>
				(KrankGetModuleListByOrder(ListOrder));

			while(Modules->DllBase)
			{
				if(nullptr != Modules &&
					ModuleInformation->BaseAddress == reinterpret_cast<unsigned long>(Modules->DllBase))
				{
					Modules->BaseDllName = KRANK::DEFINITION::UNICODE_STRING{};
					Modules->FullDllName = KRANK::DEFINITION::UNICODE_STRING{};

					KRANK::DEFINITION::LIST_ENTRY * NextLink		= nullptr;
					KRANK::DEFINITION::LIST_ENTRY * PreviousLink	= nullptr;

					switch(ListOrder)
					{
					case(KRANK::MODULE::KRANK_MODULE_LIST_LOAD_ORDER):
					{
						NextLink		= Modules->InLoadOrderLinks.Flink;
						PreviousLink	= Modules->InLoadOrderLinks.Blink;
						break;
					}
					case(KRANK::MODULE::KRANK_MODULE_LIST_MEMORY_ORDER):
					{
						NextLink		= Modules->InMemoryOrderLinks.Flink;
						PreviousLink	= Modules->InMemoryOrderLinks.Blink;
						break;
					}
					case(KRANK::MODULE::KRANK_MODULE_LIST_INITIALIZATION_ORDER):
					{
						NextLink		= Modules->InMemoryOrderLinks.Flink;
						PreviousLink	= Modules->InMemoryOrderLinks.Blink;
						break;
					}
					}

					PreviousLink = NextLink;
					NextLink = PreviousLink;

					return true;
				}

				switch(ListOrder)
				{
				case(KRANK::MODULE::KRANK_MODULE_LIST_LOAD_ORDER):
				{
					Modules = reinterpret_cast<decltype(Modules)>(Modules->InLoadOrderLinks.Flink);
					break;
				}
				case(KRANK::MODULE::KRANK_MODULE_LIST_MEMORY_ORDER):
				{
					Modules = reinterpret_cast<decltype(Modules)>(Modules->InMemoryOrderLinks.Flink);
					break;
				}
				case(KRANK::MODULE::KRANK_MODULE_LIST_INITIALIZATION_ORDER):
				{
					Modules = reinterpret_cast<decltype(Modules)>(Modules->InInitializationOrderLinks.Flink);
					break;
				}
				}
			}

			return false;
		}

		auto KrankHideModulePages(
			KRANK_MODULE_INFORMATION * ModuleInformation		
		) -> bool
		{
			using f_NtQueryVirtualMemory = long(__stdcall*)(
				void*,
				void*,
				KRANK::DEFINITION::MEMORY_INFORMATION_CLASS,
				void*,
				unsigned long,
				unsigned long *
				);

			KRANK_MODULE_INFORMATION NtDll = KrankGetModule(L"ntdll.dll", KRANK_MODULE_LIST_LOAD_ORDER);

			f_NtQueryVirtualMemory NtQueryVirtualMemory = reinterpret_cast<decltype(NtQueryVirtualMemory)>
				(KrankGetFunction(&NtDll, "NtQueryVirtualMemory"));

			KRANK::DEFINITION::MEMORY_BASIC_INFORMATION Mbi = decltype(Mbi){};

			unsigned long CurrentAddress = 0x0;

			while(0 <= NtQueryVirtualMemory((void*)-1, reinterpret_cast<void*>(CurrentAddress), 
				KRANK::DEFINITION::MEMORY_INFORMATION_CLASS::MemoryBasicInformation, &Mbi, sizeof(Mbi),
				nullptr))
			{
				KRANK::DEFINITION::SECTION_INFO SectionInformation;

				if(0x01000000 == Mbi.Type)
				{
					if(0 <= NtQueryVirtualMemory((void*)-1, reinterpret_cast<void*>(CurrentAddress), 
						KRANK::DEFINITION::MEMORY_INFORMATION_CLASS::MemoryMappedFilenameInformation,
						&SectionInformation, sizeof(SectionInformation), nullptr))
					{
						KRANK::TEXT::KrankCopyTextW(SectionInformation.DataBuffer, L" ", 
							SectionInformation.Length);

						for(int i = 0; i < sizeof(SectionInformation.Data); ++i)
						{
							SectionInformation.Data[i] = 0x0;
						}

						SectionInformation.Length			= 0;
						SectionInformation.MaximumLength	= 0;

						return true;
					}
				}

				CurrentAddress = (CurrentAddress + Mbi.RegionSize);
			}

			return false;
		}

		auto KrankHideModule(
			KRANK_MODULE_INFORMATION * ModuleInformation
		) -> bool
		{
			if(KrankHideModulePeb(ModuleInformation, KRANK_MODULE_LIST_LOAD_ORDER))
			{
				if(KrankHideModulePages(ModuleInformation))
				{
					return true;
				}
			}

			return false;
		}
	}
}

#endif