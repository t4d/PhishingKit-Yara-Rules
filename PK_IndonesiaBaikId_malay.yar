rule PK_IndonesiaBaikId_malay : IndonesiaBaik
{
    meta:
        description = "Phishing Kit impersonating Indonesia Baik id"
        licence = "AGPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2025-01-13"
        comment = "Phishing Kit - IndonesiaBaik.id - 'MALAY RESS'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "assets"
        $spec_dir2 = "img"
        $spec_dir3 = "js"
        $spec_file1 = "telegram.php"
        $spec_file2 = "thirdData.php"
        $spec_file3 = "index.js"
        $spec_file4 = "404.html"
        $spec_file5 = "ini1.jpg"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
