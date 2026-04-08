rule PK_AR24_tg : AR24
{
    meta:
        description = "Phishing Kit impersonating AR24"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2026-04-08"
        comment = "Phishing Kit - AR24 - Using Telegram"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "files"
        $spec_dir2 = "img"
        $spec_file = "TelegramApi.php"
        $spec_file2 = "error1.php"
        $spec_file3 = "all.png"
        $spec_file4 = "regionalsace_grey.png"
        $spec_file5 = "AR24.svg"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and 
        all of ($spec_file*)
}
