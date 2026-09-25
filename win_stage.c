#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include <wchar.h>

/* Trova il volume ESP che contiene \EFI\MyApp\payload.exe */
static BOOL
find_esp_root(wchar_t *OutRoot, size_t OutCch)
{
    wchar_t VolumeName[MAX_PATH];
    HANDLE  h = FindFirstVolumeW(VolumeName, MAX_PATH);
    if (h == INVALID_HANDLE_VALUE) return FALSE;

    BOOL Found = FALSE;
    do {
        wchar_t Probe[MAX_PATH];
        _snwprintf(Probe, MAX_PATH, L"%sEFI\\MyApp\\payload.exe", VolumeName);
        Probe[MAX_PATH - 1] = L'\0';
        DWORD Attr = GetFileAttributesW(Probe);
        if (Attr != INVALID_FILE_ATTRIBUTES && !(Attr & FILE_ATTRIBUTE_DIRECTORY)) {
            wcsncpy(OutRoot, VolumeName, OutCch - 1);
            OutRoot[OutCch - 1] = L'\0';
            Found = TRUE;
            break;
        }
    } while (FindNextVolumeW(h, VolumeName, MAX_PATH));
    FindVolumeClose(h);
    return Found;
}

static BOOL
run_payload_once(const wchar_t *EspRoot)
{
    wchar_t Payload[MAX_PATH], Flag[MAX_PATH];
    wchar_t TempDir[MAX_PATH], TempPayload[MAX_PATH];

    _snwprintf(Payload, MAX_PATH, L"%sEFI\\MyApp\\payload.exe", EspRoot);
    _snwprintf(Flag,    MAX_PATH, L"%sEFI\\MyApp\\run.flag",    EspRoot);

    if (GetFileAttributesW(Flag) != INVALID_FILE_ATTRIBUTES) {
        wprintf(L"[win_stage] run.flag presente: payload gia' eseguito.\n");
        return TRUE;
    }

    if (GetFileAttributesW(Payload) == INVALID_FILE_ATTRIBUTES) {
        wprintf(L"[win_stage] payload.exe non trovato sulla ESP.\n");
        return FALSE;
    }

    GetTempPathW(MAX_PATH, TempDir);
    _snwprintf(TempPayload, MAX_PATH, L"%swin_stage_payload.exe", TempDir);
    if (!CopyFileW(Payload, TempPayload, FALSE)) {
        wprintf(L"[win_stage] CopyFile fallita: %lu\n", GetLastError());
        return FALSE;
    }

    STARTUPINFOW        si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);

    if (!CreateProcessW(NULL, TempPayload, NULL, NULL, FALSE, 0,
                        NULL, NULL, &si, &pi)) {
        wprintf(L"[win_stage] CreateProcess fallita: %lu\n", GetLastError());
        DeleteFileW(TempPayload);
        return FALSE;
    }
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    HANDLE hFlag = CreateFileW(Flag, GENERIC_WRITE, 0, NULL,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFlag != INVALID_HANDLE_VALUE) {
        DWORD w;
        WriteFile(hFlag, "done", 4, &w, NULL);
        CloseHandle(hFlag);
        wprintf(L"[win_stage] payload eseguito e run.flag creato.\n");
    } else {
        wprintf(L"[win_stage] flag fallito: %lu\n", GetLastError());
    }
    return TRUE;
}

int
wmain(int argc, wchar_t **argv)
{
    (void)argc; (void)argv;
    wchar_t EspRoot[MAX_PATH] = {0};
    if (!find_esp_root(EspRoot, MAX_PATH)) {
        wprintf(L"[win_stage] ESP non trovata o payload assente.\n");
        return 1;
    }
    wprintf(L"[win_stage] ESP: %ls\n", EspRoot);
    return run_payload_once(EspRoot) ? 0 : 2;
}