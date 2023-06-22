rule PK_ING_asefi : ING
{
    meta:
        description = "Phishing Kit impersonating ING bank"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-06-06"
        comment = "Phishing Kit - ING bank - '- 07-asefi -'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "ing"
        $spec_dir2 = "ING Login_fichiers"

        $spec_file1 = "ba.php"
        $spec_file2 = "s-crer.php"
        $spec_file3 = "st-nr.php"
        $spec_file4 = "4747a12d1320e019224f7a17da333a3d.png"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}