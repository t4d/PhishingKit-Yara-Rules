rule PK_Bunq_kaktys : Bunq
{
    meta:
        description = "Phishing Kit impersonating Bunq"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = "https://krebsonsecurity.com/2021/02/arrest-raids-tied-to-u-admin-phishing-kit/"
        date = "2024-05-15"
        comment = "Phishing Kit - Bunq - 'kaktys home_email file'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_file1 = "gate.php"
        $spec_file2 = "Bericht.html"
        $spec_file3 = "login2.php"
        $spec_file4 = "index2.php"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        // check for file
        all of ($spec_file*)
}
