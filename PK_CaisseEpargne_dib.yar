rule PK_CaisseEpargne_dib : CaisseEpargne
{
    meta:
        description = "Phishing Kit impersonating Caisse d'Epargne"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-11-21"
        comment = "Phishing Kit - Caisse d'Epargne - using several pieces of code and a specific 'dib' directory"

    strings:
        // the zipfile working on
        $local_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "dib"
        $spec_dir2 = "pass_files"
        // specific files found in PhishingKit
        $spec_file = "certi.html"
        $spec_file2 = "graphisme-jo-ce.svg"
        $spec_file3 = "carte.php"
        $spec_file4 = "securi.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and 
	   $local_file and 
	   all of ($spec_dir*) and 
	   all of ($spec_file*)
}
