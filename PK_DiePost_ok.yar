rule PK_DiePost_ok : DiePost
{
    meta:
        description = "Phishing Kit impersonating Die Post"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-04-20"
        comment = "Phishing Kit - DiePost - '~ ok ~ also known as GovCERTch phishing kit ;p'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "sms1_files"
        $spec_file1 = "sm.php"
        $spec_file2 = "sm1.php"
        $spec_file3 = "att1.html"
        $spec_file4 = "sn.php"
        $spec_file5 = "icon-viza.png"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        $spec_dir and
        // check for file
        all of ($spec_file*)
}
