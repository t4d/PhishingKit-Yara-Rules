rule PK_Correos_argcc : Correos
{
    meta:
        description = "Phishing Kit impersonating Correos Argentina"
        licence = "AGPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-11-14"
        comment = "Phishing Kit - Correos - 'CorreoARG'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "send"
        $spec_dir2 = "styles"
        $spec_dir3 = "javascript"
        $spec_file1 = "result-telegram.php"
        $spec_file2 = "send2.php"
        $spec_file3 = "codigo.Css"
        $spec_file4 = "junia.js"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
