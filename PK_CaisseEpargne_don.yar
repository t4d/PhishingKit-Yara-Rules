rule PK_CaisseEpargne_don : CaisseEpargne
{
    meta:
        description = "Phishing Kit impersonating Caisse d'Epargne"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = "https://stalkphish.com/2024/01/27/phishing-kit-caisse-epargne-don-an-analysis/"
        date = "2023-12-29"
        comment = "Phishing Kit - Caisse d'Epargne - 'From:Trnswise <don@mox.fr>'"

    strings:
        // the zipfile working on
        $local_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "Caisse"
        $spec_dir2 = "pass_files"
        // specific files found in PhishingKit
        $spec_file = "certi2.html"
        $spec_file2 = "graphisme-jo-ce.svg"
        $spec_file3 = "normal.php"
        $spec_file4 = "bpce-icons.ttf"
        $spec_file5 = "gamme-assurance-generique_push_marketing.jpg"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and 
	   $local_file and 
	   all of ($spec_dir*) and 
	   all of ($spec_file*)
}
