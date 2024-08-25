rule PK_Instagram_center : Instagram
{
    meta:
        description = "Phishing Kit impersonating Instagram"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-08-20"
        comment = "Phishing Kit - Instagram - using mixed appeal-center-support words as directory"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "Instagram_files"
        $spec_dir2 = "centersupportappeal-main"
        $spec_file1 = "incorrect.html"
        $spec_file2 = "badge_android_english-en.png"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
