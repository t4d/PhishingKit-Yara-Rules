rule PK_InPost_evilc : InPost
{
    meta:
        description = "Phishing Kit impersonating InPost PL"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-05-10"
        comment = "Phishing Kit - InPost - '-BY @evilcoder1337'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "INPOST_result"
        $spec_dir2 = "evil_coder"
        $spec_dir3 = "main"
        $spec_file1 = "evilc_address.php"
        $spec_file2 = "exit.php"
        $spec_file3 = "Fuck-you.php"
        $spec_file4 = "evilc_sms.php"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
