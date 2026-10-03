rule PK_Gmail_canada : GMail
{
    meta:
        description = "Phishing Kit - impersonating GMail"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2026-09-30"
        comment = "Phishing Kit - GMail - '-|CANADA|-'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "Google_docs_files"
        $spec_dir2 = "SpryAssets"
        $spec_file = "verification.php"
        $spec_file2 = "geoplugin.class.php"
        $spec_file3 = "googledocs.jpg"
        $spec_file4 = "universal_language_settings-21.png"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and 
        $zip_file and 
        all of ($spec_dir*) and 
        all of ($spec_file*)
}
