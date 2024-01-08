rule PK_American1CU_prohqcker : American1
{
    meta:
        description = "Phishing Kit impersonating American 1 Credit Union"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-12-07"
        comment = "Phishing Kit - American1 - 'Prohqcker_Bot*A1CU*'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "css"
        $spec_dir1 = "img"
        $spec_file1 = "me.php"
        $spec_file2 = "prohqcker4.php"
        $spec_file3 = "MaterialIcons-Regular.4.0.2.ttf"
        $spec_file4 = "equal-housing.png"
        $spec_file5 = "styles.9dd25dcfcda7df4e.css"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
