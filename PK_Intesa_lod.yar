rule PK_Intesa_lod : Intesa
{
    meta:
        description = "Phishing Kit impersonating Intesa Sanpaolo"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2023-01-09"
        comment = "Phishing Kit - Intesa - using 'lod.php' file"

    strings:
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "summary"
        $spec_dir2 = "Files2"
        // specific files found in PhishingKit
        $spec_file1 = "done.php"
        $spec_file2 = "lod.php"
        $spec_file3 = "OS-Platform.php"
        $spec_file4 = "Casa.png"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and 
        all of ($spec_dir*) and 
        all of ($spec_file*)
}
