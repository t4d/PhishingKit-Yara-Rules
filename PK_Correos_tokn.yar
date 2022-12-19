rule PK_Correos_tokn : Correos
{
    meta:
        description = "Phishing Kit impersonating Correos"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-12-01"
        comment = "Phishing Kit - Correos - 'using $tokn variable for Telegram exfiltration"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "boots"
        $spec_dir2 = "Bienvenido a Correos.es - El Portal Online de Correos_files"
        $spec_file1 = "sigue_tu_envio.svg"
        $spec_file2 = "pin.php"
        $spec_file3 = "telegram.php"
        $spec_file4 = "correos-ui-kit.css"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and 
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
