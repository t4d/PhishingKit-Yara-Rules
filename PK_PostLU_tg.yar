rule PK_PostLU_tg : PostLU
{
    meta:
        description = "Phishing Kit impersonating POST Luxembourg"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2023-05-02"
        comment = "Phishing Kit - PostLU - using telegram for exfiltration"

    strings:
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "colis"
        $spec_dir2 = "Luxtrust_files"
        // specific files found in PhishingKit
        $spec_file1 = "0.php"
        $spec_file2 = "trust.html"
        $spec_file3 = "store-loading.php"
        $spec_file4 = "lux1.png"


    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and 
        all of ($spec_file*)
}
