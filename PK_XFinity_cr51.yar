rule PK_XFinity_cr51 : XFinity
{
    meta:
        description = "Phishing Kit impersonating XFinity/Comcast"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-08-01"
        comment = "Phishing Kit - XFinity - CR51"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "Assets"
        $spec_dir2 = "kintil"
        $spec_dir3 = "Views"
        $spec_dir4 = "install"

        $spec_file1 = "cr51.htaccess"
        $spec_file2 = "cr51blocker.php"
        $spec_file3 = "Myaccount.php"
        $spec_file4 = "xfinitybrown-bold.woff2"
        $spec_file5 = "cr51.install.style.css"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
