rule PK_Alibaba_whizkossy : Alibaba
{
    meta:
        description = "Phishing Kit impersonating Alibaba"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-03-14"
        comment = "Phishing Kit - Alibaba - '=By whizkossy d bad guy='"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "files"
        $spec_dir2 = "images"
        $spec_file1 = "index975f.php"
        $spec_file2 = "log.js"
        $spec_file3 = "big-brother.js"
        $spec_file4 = "wrong details.png"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
