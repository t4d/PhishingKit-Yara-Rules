rule PK_HKPost_blackforce : HKPost
{
    meta:
        description = "Phishing Kit impersonating HongKong Post"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-08-22"
        comment = "Phishing Kit - HKPost - 'BLACKFORCE REZDATA'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "fastCardLink"
        $spec_dir2 = "botActBan"
        $spec_file1 = "7wiwmoSms.php"
        $spec_file2 = "ZKZg.gif.mp4"
        $spec_file3 = "index_send.php"
        $spec_file4 = "hkp_logo_bw.png"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
