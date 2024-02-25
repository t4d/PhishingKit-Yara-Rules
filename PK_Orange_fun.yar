rule PK_Orange_fun : Orange
{
    meta:
        description = "Phishing Kit impersonating Orange"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-01-24"
        comment = "Phishing Kit - Orange - 'fun.php' page"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific file found in PhishingKit
        $spec_file = "password.php"
        $spec_file2 = "finish.php"
        $spec_file3 = "fun.php"
	    $spec_file4 = "logo-orange.png"
        $spec_file5 = "fin.html"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        // check for file
        all of ($spec_file*)
}
