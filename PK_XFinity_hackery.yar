rule PK_XFinity_hackery : XFinity
{
    meta:
        description = "Phishing Kit impersonating XFinity/Comcast"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-05-26"
        comment = "Phishing Kit - XFinity - 'F0rg3d By Hackery'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "idm"
        $spec_dir2 = "js"

        $spec_file1 = "cid.php"
        $spec_file2 = "CmaxAuthnAge.php"
        $spec_file3 = "erlogin.php"
        $spec_file4 = "xfinity-logo-grey.svg"
        $spec_file5 = "comcast-common.js"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
