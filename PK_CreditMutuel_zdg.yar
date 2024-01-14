rule PK_CreditMutuel_zdg : CreditMutuel
{
    meta:
        description = "Phishing Kit impersonating Credit Mutuel"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-11-11"
        comment = "Phishing Kit - Credit Mutuel - file named 'ZDG-phishing.jpg'"

    strings:
        // the zipfile working on
        $local_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "upload"
        $spec_dir2 = "css"
        $spec_dir3 = "image"
        // specific files found in PhishingKit
        $spec_file = "infos.php"
        $spec_file2 = "upload.php"
        $spec_file3 = "visitors.html"
        $spec_file4 = "ZDG-phishing.jpg"
        $spec_file5 = "upl.jpg"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and 
	   $local_file and 
	   all of ($spec_dir*) and 
	   all of ($spec_file*)
}
