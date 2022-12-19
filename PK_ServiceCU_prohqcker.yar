rule PK_ServiceCU_prohqcker : ServiceCreditUnion
{
    meta:
        description = "Phishing Kit impersonating Service Credit Union"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-11-02"
        comment = "Phishing Kit - Service Credit Union - '**Telegram ID: @prohqcker *Service***'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir1 = "img"
        $spec_dir2 = "js"
        $spec_file1 = "ncua.png"
        $spec_file2 = "otp.html"
        $spec_file3 = "me.php"
        $spec_file4 = "db_connect4.php"
        $spec_file5 = "c.html"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
