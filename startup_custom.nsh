cls
fs0:
cd \EFI\EfiStage\keys
UpdateVars.efi -f PK.auth PK
UpdateVars.efi -f KEK.auth KEK
UpdateVars.efi -f db.auth db
reset