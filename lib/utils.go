package lib

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"syscall"
	"unsafe"
)

func findASMDll(fName, dll string) ([]byte, error) {
	var r = []byte{}
	pSourceBytes, err := os.ReadFile(dll)
	if err != nil {
		return r, err
	}

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

	var exportDir = new(IMAGE_DATA_DIRECTORY)
	rdrBytes = bytes.NewReader(pSourceBytes[ntHeaderOffset+LONG(unsafe.Sizeof(IMAGE_NT_HEADERS{}.Signature)+unsafe.Sizeof(IMAGE_NT_HEADERS{}.FileHeader)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.Magic)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.MajorLinkerVersion)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.MinorLinkerVersion)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.SizeOfCode)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.SizeOfInitializedData)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.SizeOfUninitializedData)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.AddressOfEntryPoint)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.BaseOfCode)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.ImageBase)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.SectionAlignment)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.FileAlignment)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.MajorOperatingSystemVersion)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.MinorOperatingSystemVersion)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.MajorImageVersion)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.MinorImageVersion)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.MajorSubsystemVersion)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.MinorSubsystemVersion)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.Win32VersionValue)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.SizeOfImage)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.SizeOfHeaders)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.CheckSum)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.Subsystem)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.DllCharacteristics)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.SizeOfStackReserve)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.SizeOfStackCommit)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.SizeOfHeapReserve)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.SizeOfHeapCommit)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.LoaderFlags)+unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}.NumberOfRvaAndSizes)):])
	err = binary.Read(rdrBytes, binary.LittleEndian, exportDir)
	if err != nil {
		return r, err
	}

	offset, err := findOffset(pOldNtHeader, uintptr(ntHeaderOffset), pSourceBytes, exportDir.VirtualAddress)
	if err != nil {
		return r, err
	}

	var exporttable = IMAGE_EXPORT_DIRECTORY{}
	rdrBytes = bytes.NewReader(pSourceBytes[exportDir.VirtualAddress+offset:])
	err = binary.Read(rdrBytes, binary.LittleEndian, &exporttable)
	if err != nil {
		return r, err
	}

	for i := 0; i < int(exporttable.NumberOfFunctions); i++ {
		var nameAddr DWORD
		rdrBytes = bytes.NewReader(pSourceBytes[LONG(exporttable.AddressOfNames+offset+DWORD(i*4)):])
		err = binary.Read(rdrBytes, binary.LittleEndian, &nameAddr)
		if err != nil {
			return r, err
		}
		name := bytePtrToString((*byte)(unsafe.Pointer(&pSourceBytes[nameAddr+offset])))
		var funcAddr DWORD
		rdrBytes = bytes.NewReader(pSourceBytes[LONG(exporttable.AddressOfFunctions+offset+DWORD((i+1)*4)):])
		err = binary.Read(rdrBytes, binary.LittleEndian, &funcAddr)
		if err != nil {
			return r, err
		}
		offset, err := findOffset(pOldNtHeader, uintptr(ntHeaderOffset), pSourceBytes, funcAddr)
		if err != nil {
			return r, err
		}

		if name == fName {
			counter := 0
			for {
				b := pSourceBytes[LONG(funcAddr+offset):][counter]
				r = append(r, b)
				if b == 0xc3 {
					break
				}
				counter++
			}
			break
		}
	}

	return r, nil
}

func findOffset(pOldNtHeader *IMAGE_NT_HEADERS, ntHeaderOffset uintptr, pSourceBytes []byte, address DWORD) (DWORD, error) {
	sectionHeaderOffset := uint16(ntHeaderOffset + unsafe.Sizeof(IMAGE_NT_HEADERS{}.Signature) + unsafe.Sizeof(IMAGE_NT_HEADERS{}.FileHeader) + unsafe.Sizeof(IMAGE_NT_HEADERS{}.OptionalHeader))
	var sectionHeader IMAGE_SECTION_HEADER
	const sectionHeaderSize = unsafe.Sizeof(sectionHeader)

	offset := DWORD(0)
	for i := WORD(0); i != pOldNtHeader.FileHeader.NumberOfSections; i++ {
		rdrBytes := bytes.NewReader(pSourceBytes[sectionHeaderOffset:])
		err := binary.Read(rdrBytes, binary.LittleEndian, &sectionHeader)
		if err != nil {
			return offset, err
		}

		if !(address > sectionHeader.VirtualAddress) {
			break
		} else {
			offset = -sectionHeader.VirtualAddress + sectionHeader.PointerToRawData
		}

		sectionHeaderOffset = sectionHeaderOffset + uint16(sectionHeaderSize)
	}

	return offset, nil
}

func writeMemory(addr uintptr, data []byte) {
	for _, b := range data {
		*(*byte)(unsafe.Pointer(addr)) = b
		addr = addr + 0x1
	}
}

func bytePtrToString(p *byte) string {
	if p == nil {
		return ""
	}
	if *p == 0 {
		return ""
	}

	n := 0
	for ptr := unsafe.Pointer(p); *(*byte)(ptr) != 0; n++ {
		ptr = unsafe.Pointer(uintptr(ptr) + 1)
	}

	return string(unsafe.Slice(p, n))
}

func decrypt(cipherstring string, keystring string) ([]byte, error) {
	ciphertext := []byte(cipherstring)

	key := []byte(keystring)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < aes.BlockSize {
		return nil, errors.New("text is too short")
	}

	iv := ciphertext[:aes.BlockSize]

	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)

	stream.XORKeyStream(ciphertext, ciphertext)

	return ciphertext, nil
}

func encrypt(plainstring, keystring string) ([]byte, error) {
	plaintext := []byte(plainstring)

	key := []byte(keystring)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))

	iv := ciphertext[:aes.BlockSize]

	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	stream := cipher.NewCFBEncrypter(block, iv)

	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	return ciphertext, nil
}

const sizeOfUintPtr = unsafe.Sizeof(uintptr(0))

func uintptrToBytes(u *uintptr) []byte {
	return (*[sizeOfUintPtr]byte)(unsafe.Pointer(u))[:]
}

func readAddrFunc(currentProcess syscall.Handle, addr uintptr) uintptr {
	var testAddr = [8]byte{}
	var outSize uintptr
	ReadProcessMemory(currentProcess, addr, &testAddr[0], uintptr(len(testAddr)), &outSize)

	var r uintptr
	for i := 7; i >= 0; i-- {
		r = (r << 8) | uintptr(testAddr[i])
	}
	ReadProcessMemory(currentProcess, r, &testAddr[0], uintptr(len(testAddr)), &outSize)
	for i := 7; i >= 0; i-- {
		r = (r << 8) | uintptr(testAddr[i])
	}
	return r
}
