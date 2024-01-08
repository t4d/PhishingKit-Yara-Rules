rule PK_BNP_seiko : BNP
{
    meta:
        description = "Phishing Kit impersonating BNP Paribas"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-11-06"
        comment = "Phishing Kit - BNP - 'AUTHOR :  SEIKO'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "panel"
        $spec_dir2 = "app"
        $spec_dir3 = "BNPPARIBAS_files"
        $spec_file1 = "md.php"
        $spec_file2 = "covid19-information.png"
        $spec_file3 = "panel.class.php"
        $spec_file4 = "dciweb.png"
        $spec_file5 = "tan.php"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
