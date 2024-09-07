rule PK_antai_inun : ANTAI
{
    meta:
        description = "Phishing Kit impersonating French ANTAI (amendes) portal"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = "https://www.linkedin.com/feed/update/urn:li:activity:7237346969864605697/?actorCompanyId=71551425"
        date = "2024-09-05"
        comment = "Phishing Kit - ANTAI - 'info@INUN.bg'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "infos_files"
        $spec_dir2 = "infoz"
        $spec_file1 = "3dsece.php"
        $spec_file2 = "otpp.php"
        $spec_file3 = "cc.php"
        $spec_file4 = "sub_includes.php"
        $spec_file5 = "logo-amendes-gouv.svg"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and 
        all of ($spec_dir*) and 
        all of ($spec_file*)
}
