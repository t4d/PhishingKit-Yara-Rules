rule PK_CIHBank_gcsteam : CIHBank
{
    meta:
        description = "Phishing Kit impersonating CIHBank"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2023-01-13"
        comment = "Phishing Kit - CIHBank - 'GCS-Team CIH Bank'"

    strings:
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "files"
        $spec_dir2 = "img"
        // specific files found in PhishingKit
        $spec_file1 = "email.php"
        $spec_file2 = "send.php"
        $spec_file3 = "javascriptfile15.js"
        $spec_file4 = "logo_cihbank.png"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and 
        all of ($spec_dir*) and 
        all of ($spec_file*)
}
