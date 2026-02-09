rule PK_Netflix_flag : Netflix
{
    meta:
        description = "Phishing Kit impersonating Netflix"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2026-02-09"
        comment = "Phishing Kit - Netflix - Use dedicated flags file"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "plain_files"
        $spec_dir2 = "sys"
        $spec_dir3 = "anti"
        $spec_file = "cc.php"
        $spec_file2 = "flag.php"
        $spec_file3 = "main.js"
        $spec_file4 = "Netflix_Logo_PMS.png"
        $spec_file5 = "blacklist_lookup.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
