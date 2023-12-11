rule PK_InPost_ovni : InPost
{
    meta:
        description = "Phishing Kit impersonating InPost PL"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-12-11"
        comment = "Phishing Kit - InPost - using $...ovni variables"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "libs"
        $spec_dir2 = "menu"
        $spec_dir3 = "panel"
        $spec_dir4 = "eleirbag89"
        $spec_file1 = "DesktopBlock.php"
        $spec_file2 = "eroor2.php"
        $spec_file3 = "ovni.js"
        $spec_file4 = "inpost-partnerem-strategicznym-open-eyes-economy-summit-2023-1758538.png"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
