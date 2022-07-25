rule PK_Suncorp_zeb : Suncorp
{
    meta:
        description = "Phishing Kit impersonating Suncorp"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-07-18"
        comment = "Phishing Kit - Suncorp - using zeb.php file and a 'zebtech1' admin panel"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir1 = "visitors"
        $spec_dir2 = "CrawlerDetect"
        $spec_file1 = "zeb.php"
        $spec_file2 = "cancel-payment.php"
        $spec_file3 = "profile.php"
        $spec_file4 = "ReferralSpamDetect.php"
        $spec_file5 = "one_time_br_prevents.log"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
