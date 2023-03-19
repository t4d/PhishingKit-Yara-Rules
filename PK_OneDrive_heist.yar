rule PK_OneDrive_heist : OneDrive
{
    meta:
        description = "Phishing Kit impersonating OneDrive"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-03-15"
        comment = "Phishing Kit - OneDrive - 'From: /Heist-InMotion'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "cgi-bin"
        // specific file found in PhishingKit
        $spec_file = "next.php"
        $spec_file2 = "index.html"
        $spec_file3 = "1.html"
	    $spec_file4 = "1.png"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        // check for file
        $spec_dir and 
        all of ($spec_file*)
}
