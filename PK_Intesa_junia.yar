rule PK_Intesa_junia : Intesa
{
    meta:
        description = "Phishing Kit impersonating Intesa Sanpaolo"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-04-05"
        comment = "Phishing Kit - Intesa - 'Main author : Junia'"

    strings:
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "php"
        $spec_dir2 = "images"
        // specific files found in PhishingKit
        $spec_file1 = "loading-log.php"
        $spec_file2 = "sms-error.php"
        $spec_file3 = "junia-framework.js"
        $spec_file4 = "logo-intesasanpaolo.png"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and 
        all of ($spec_dir*) and 
        all of ($spec_file*)
}
