rule PK_Orange_fnetwork : Orange
{
    meta:
        description = "Phishing Kit impersonating Orange"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2023-02-18"
        comment = "Phishing Kit - Orange - 'BY Mr.fnetwork'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "Identifiez-vous avec votre compte Orange_fichiers"
        $spec_dir2 = "password_fichiers"
        // specific file found in PhishingKit
        $spec_file = "finish.php"
        $spec_file2 = "password.php"
        $spec_file3 = "pubads_impl_2020120701.js"
	    $spec_file4 = "567x302_OBANK_Levier01_PUSH_20201109a.jpg"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        // check for file
        all of ($spec_file*) and 
	    all of ($spec_dir*)
}
