rule PK_ScotiaBank_unknownhax0r : ScotiaBank
{
    meta:
        description = "Phishing Kit impersonating Scotia bank"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2026-05-15"
        comment = "Phishing Kit - Scotia bank - 'FROM: Unknown Haxor'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "backend"
        $spec_file1 = "bb.scotia_online.htm"
        $spec_file2 = "Scotia_success.php"
        $spec_file3 = "BB_landing.php"
        $spec_file4 = "bk3.php"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        $spec_dir and
        // check for file
        all of ($spec_file*)
}
