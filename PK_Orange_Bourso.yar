rule PK_Orange_Bourso : Orange
{
    meta:
        description = "Phishing Kit impersonating Orange"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-01-08"
        comment = "Phishing Kit - Orange - based on a z0n51 Boursorama kit"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "sass"
        $spec_dir1 = ""
        $spec_dir2 = ""
        // specific file found in PhishingKit
        $spec_file = "ss1.php"
        $spec_file2 = "opass.php"
        $spec_file3 = "ologin.php"
	    $spec_file4 = "app.php"
        $spec_file5 = "ologo.png"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and
        all of ($spec_file*)
}
