rule PK_OneDrive_ishuman : OneDrive
{
    meta:
        description = "Phishing Kit impersonating OneDrive"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-06-28"
        comment = "Phishing Kit - OneDrive - 'COOKIE[ishuman]'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "data"
        // specific file found in PhishingKit
        $spec_file = "rs.php"
        $spec_file2 = "email.php"
        $spec_file3 = "meta.php"
	    $spec_file4 = "geoplugin.class.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        // check for file
        $spec_dir and 
        all of ($spec_file*)
}
