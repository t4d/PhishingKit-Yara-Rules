rule PK_DHL_widibaz : DHL
{
    meta:
        description = "Phishing Kit impersonating DHL"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2023-04-15"
        comment = "Phishing Kit - DHL - name based on Telegram bot name"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "fedex3"
        $spec_file1 = "fedex6.php"
        $spec_file2 = "infoclien.txt"
        $spec_file4 = "pub.jpg"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
