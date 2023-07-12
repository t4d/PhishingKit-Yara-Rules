rule PK_BNP_texlon : BNP
{
    meta:
        description = "Phishing Kit impersonating BNP Paribas"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-07-10"
        comment = "Phishing Kit - BNP - 'Created By TEXLON'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "BNPPARIBAS_files"
        $spec_file1 = "bnp1.php"
        $spec_file2 = "DSP2Authentification.htm"
        $spec_file3 = "BNPPARIBAS.html"
        $spec_file4 = "covid19-information.png"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
