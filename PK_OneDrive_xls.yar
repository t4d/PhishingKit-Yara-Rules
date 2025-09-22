rule PK_OneDrive_xls : OneDrive
{
    meta:
        description = "Phishing Kit impersonating OneDrive"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-09-10"
        comment = "Phishing Kit - OneDrive - '-| xLs |-'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "SpryAssets"
        $spec_dir2 = "dbx"
        $spec_dir3 = "sharedfolder"
        $spec_file = "view.html"
        $spec_file2 = "next.php"
        $spec_file3 = "Google Docs.png"
	    $spec_file4 = "onedriveside2.jpg"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_file*) and 
        all of ($spec_dir*)
}
