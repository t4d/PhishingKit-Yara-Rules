rule PK_DeutscheBank_db: DeutscheBank
{
    meta:
        description = "Phishing Kit impersonating DeutscheBank"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-07-18"
        comment = "Phishing Kit - DeutscheBank - use a SQLite DB"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "admincp"
        $spec_dir2 = "trxmcontent"
        $spec_file1 = "nachprufung.html"
        $spec_file2 = "account_sessionAuth.html"
        $spec_file3 = "DbConfig.php"
        $spec_file4 = "tlgrm.php"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
