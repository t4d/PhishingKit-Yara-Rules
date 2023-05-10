rule PK_GMX_keo : GMX
{
    meta:
        description = "Phishing Kit - impersonating GMX"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-05-10"
        comment = "Phishing Kit - GMX - using file like keokeo"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "Mobile Login1_files"
        $spec_dir1 = "Mobile Login_files"
        // specific file found in PhishingKit
        $spec_file = "1.php"
        $spec_file2 = "2.php"
        $spec_file3 = "index2.html"
        $spec_file4 = "pl-m-frame-asp.html"
        $spec_file5 = "gmx_banner_mailapp_android_v3.gif"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
