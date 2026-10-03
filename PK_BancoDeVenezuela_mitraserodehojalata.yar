rule PK_BancoDeVenezuela_mitraserodehojalata : BancoDeVenezuela
{
    meta:
        description = "Phishing Kit impersonating Banco De Venezuela"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2026-09-23"
        comment = "Phishing kit impersonating Banco De Venezuela - '[ @mitraserodehojalata ]'"        

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "guardian"
        $spec_dir2 = "config"
        $spec_file = "mask.php"
        $spec_file2 = "digitos-token.php"
        $spec_file3 = "cargandodos.php"
        $spec_file4 = "validar.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
