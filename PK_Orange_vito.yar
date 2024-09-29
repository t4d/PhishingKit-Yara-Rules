rule PK_Orange_vito : Orange
{
    meta:
        description = "Phishing Kit impersonating Orange"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-09-24"
        comment = "Phishing Kit - Orange - 'VITO'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "avis"
        $spec_dir2 = "selfie"
        $spec_dir3 = "actions"
        // specific file found in PhishingKit
        $spec_file = "cross-selfie.php"
        $spec_file2 = "second2.php"
        $spec_file3 = "identifiant.php"
	    $spec_file4 = "small-logo-orange.svg"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        // check for file
        all of ($spec_file*) and 
	    all of ($spec_dir*)
}
