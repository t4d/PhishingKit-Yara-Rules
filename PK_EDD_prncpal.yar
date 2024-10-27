rule PK_EDD_prncpal : EDD
{
    meta:
        description = "Phishing Kit impersonating Employment Development Department California (EDD)"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-09-30"
        comment = "Phishing Kit - EDD - 'EDD UI ONLINE-Prncpal'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "edd_fonts"
        $spec_dir2 = "ca_images"
        // specific file found in PhishingKit
        $spec_file = "2fa2.html"
        $spec_file2 = "info_dl.html"
        $spec_file3 = "me.php"
        $spec_file4 = "cagov.core.js"
        $spec_file5 = "myEDD-BG-2.png"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
