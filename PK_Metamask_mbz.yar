rule PK_Metamask_mbz : Metamask
{
    meta:
        description = "Phishing Kit impersonating Metamask"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2026-06-06"
        comment = "Phishing Kit - Metamask - '/home/mbzbest/'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "meta"
        $spec_file1 = "actionn.php"
        $spec_file2 = "verify.php"
        $spec_file3 = "verify-check.php"
        $spec_file4 = "error_log"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        $spec_dir and
        // check for file
        all of ($spec_file*)
}
