# Sample_BootKit-Gate
Sample Bootkit for Windows

**Bootkit: il codice che infetta il PC prima ancora che il sistema operativo si accenda. Ecco come agisce.**


I bootkit sono tra le minacce più subdole del panorama cybersecurity. Non si limitano a infettare il sistema operativo: agiscono prima che Windows si avvii, partendo dalla partizione di boot (MBR/GPT, VBR) al bootloader, fino al firmware UEFI. Opera quindi in fase pre-OS, con privilegi superiori a quelli del kernel stesso, e può bypassare o disattivare meccanismi di sicurezza come Secure Boot, ELAM, PatchGuard e antivirus. È di fatto un rootkit pre-OS: persistente, stealth e difficile da rimuovere anche dopo formattazione o reinstallazione del sistema operativo. 
In questo articolo documento in modo tecnico e difensivo un componente: efi_stage, un’applicazione EFI personalmente sviluppata che fa parte di una catena di persistenza pre-OS.


⚙️ **Come funziona, step by step**
Il flusso è pensato per essere trasparente all’utente: Windows si avvia normalmente, ma il payload viene rieseguito a ogni boot.
Avvio UEFI
Il firmware carica efi_stage.efi, tramite una boot entry modificata o un chainload precedente.
Inizializzazione EFI
L’applicazione inizializza la libreria EFI e stampa un messaggio di avvio.
Recupero immagine caricata
Usa HandleProtocol su ImageHandle per ottenere EFI_LOADED_IMAGE e conoscere il device di partenza.
Accesso alla ESP
Ottiene EFI_SIMPLE_FILE_SYSTEM_PROTOCOL e apre la root della EFI System Partition.
Creazione directory
Crea la directory \EFI\MyApp se non esiste.
Scrittura del payload
Scrive payload.exe (contenuto in payload.h) in \EFI\MyApp\payload.exe. Se esiste già, lo sovrascrive.
Reset del flag
Cancella \EFI\MyApp\run.flag. Questo flag serve a un componente Windows (win_stage.exe) per sapere se il payload è già stato eseguito in quel boot. Cancellandolo, il payload verrà rieseguito.
Chainload di Windows
Costruisce un device path per \EFI\Microsoft\Boot\bootmgfw.efi, lo carica con LoadImage e lo avvia con StartImage. In pratica avvia il Windows Boot Manager originale.
Windows parte normalmente
L’utente non nota nulla di anomalo.
Esecuzione del payload in Windows
Un componente Windows (win_stage.exe) controlla run.flag. Se manca, esegue payload.exe e ricrea run.flag.
Ciclo di persistenza
Al boot successivo, efi_stage cancella di nuovo run.flag. Quindi win_stage.exe rieseguirà il payload. Il ciclo si ripete.



# ⚠️ DISCLAIMER 

This repository is for **educational and defensive research purposes only**. 
The code and analysis concern a malware component (UEFI bootkit) and are provided 
**solely to understand pre-OS threats, improve detection, and train IT/security staff**.

- ❌ No instructions for compiling, installing, distributing, or using the code.
- ❌ No operational payloads, ready-to-use binaries, or attack instructions.
- ❌ No promotion, facilitation, or support of illegal activities.

The author **assumes no liability** for misuse, damage, or legal violations 
arising from the use of this information. 
Using this knowledge to attack systems without authorization is **prohibited and punishable by law**.
