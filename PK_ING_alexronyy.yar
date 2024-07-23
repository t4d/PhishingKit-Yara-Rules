rule PK_ING_alexronyy : ING
{
    meta:
        description = "Phishing Kit impersonating ING bank"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-07-22"
        comment = "Phishing Kit - ING bank - '@alexronyy'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "victims"
        $spec_dir2 = "anti__boot"
        $spec_file1 = "itan.php"
        $spec_file2 = "loading.php"
        $spec_file3 = "cc.php"
        $spec_file4 = "visitors.html"
        $spec_file5 = "i.png"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
