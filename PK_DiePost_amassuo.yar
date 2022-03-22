rule PK_DiePost_amassuo : DiePost
{
    meta:
        description = "Phishing Kit impersonating Die Post"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-03-20"
        comment = "Phishing Kit - DiePost - '- 04-amassuo -'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "Packaging"
        $spec_dir2 = "otp"
        $spec_file1 = "04-amassuo.php"
        $spec_file2 = "block_bot.txt"
        $spec_file3 = "proxyblock.php"
        $spec_file4 = "block3.php"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
