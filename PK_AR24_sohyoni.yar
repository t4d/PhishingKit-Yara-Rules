rule PK_AR24_sohyoni : AR24
{
    meta:
        description = "Phishing Kit impersonating AR24"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-05-16"
        comment = "Phishing Kit - AR24 - 'Author : Sohyoni'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "auth"
        $spec_dir2 = "includes"
        $spec_file = "configg.php"
        $spec_file2 = "inval.php"
        $spec_file3 = "forbidden.php"
        $spec_file4 = "regionalsace_grey.png"
        $spec_file5 = "AR24.png"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and 
        all of ($spec_file*)
}
