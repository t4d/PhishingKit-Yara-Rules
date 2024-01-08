rule PK_Correos_junia : Correos
{
    meta:
        description = "Phishing Kit impersonating Correos de Costa Rica"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2023-12-11"
        comment = "Phishing Kit - Correos - 'By @Junia_wolf'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "styles"
        $spec_dir2 = "send"
        $spec_file1 = "junia.js"
        $spec_file2 = "loadingend.php"
        $spec_file3 = "junia-telegram.php"
        $spec_file4 = "LogoCornamusa.svg"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
