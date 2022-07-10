rule PK_MACU_xxx : MACU
{
    meta:
        description = "Phishing Kit impersonating Mountain America Credit Union (MACU)"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-07-08"
        comment = "Phishing Kit - Mountain America Credit Union - '-xXx-'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "MACU"
        $spec_dir2 = "01macu_12"
        // specific file found in PhishingKit
        $spec_file = "9802p1.php"
        $spec_file2 = "0012p3.php"
        $spec_file3 = "grabber.php"
        $spec_file4 = "2098p4.php"
        $spec_file5 = "m.html"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of($spec_dir*) and
        // check for file
        all of ($spec_file*)
}

