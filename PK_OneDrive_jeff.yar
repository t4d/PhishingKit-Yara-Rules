rule PK_OneDrive_jeff : OneDrive
{
    meta:
        description = "Phishing Kit impersonating OneDrive"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-05-23"
        comment = "Phishing Kit - OneDrive"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific file found in PhishingKit
        $spec_file = "jeff2.php"
        $spec_file2 = "index3.php"
        $spec_file3 = "microsoft.css"
	    $spec_file4 = "other.html"
        $spec_file5 = "jeff.php"
        $spec_file6 = "office.php"
        $spec_file7 = "index.html"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and 
        all of ($spec_file*)
}