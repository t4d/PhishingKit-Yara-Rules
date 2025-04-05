rule PK_OneDrive_petnica : OneDrive
{
    meta:
        description = "Phishing Kit impersonating OneDrive"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-04-05"
        comment = "Phishing Kit - OneDrive - With a lots of 'petnica' named files"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific file found in PhishingKit
        $spec_file = "petnica.php"
        $spec_file2 = "petnica.js"
        $spec_file3 = "petnica.css"
	    $spec_file4 = "petnica3.png"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_file*)
}
