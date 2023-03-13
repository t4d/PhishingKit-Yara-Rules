rule PK_Intesa_unknown : Intesa Sanpaolo
{
    meta:
        description = "Phishing Kit impersonating Intesa Sanpaolo"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-03-03"
        comment = "Phishing Kit - Intesa Sanpaolo - '- unknown -'"

    strings:
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "users"
        $spec_dir1 = "summary"
        $spec_dir2 = "prevents"
        // specific files found in PhishingKit
        $spec_file1 = "lod.php"
        $spec_file2 = "OS-Platform.php"
        $spec_file3 = "card.php"
        $spec_file4 = "ISP_logo-01.png"


    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and 
        all of ($spec_file*)
}
