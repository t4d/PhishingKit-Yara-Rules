rule PK_OneDrive_hrm : OneDrive
{
    meta:
        description = "Phishing Kit impersonating OneDrive"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-01-29"
        comment = "Phishing Kit - OneDrive - 'Scripted by HRM'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "image"
        // specific file found in PhishingKit
        $spec_file = "ink.php"
        $spec_file2 = "style.css"
        $spec_file3 = "Jr6ZeZQ.gif"
	    $spec_file4 = "02Etp5S4bK904LpzJzjD8eA-7.jpg"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        // check for file
        $spec_dir and 
        all of ($spec_file*)
}
