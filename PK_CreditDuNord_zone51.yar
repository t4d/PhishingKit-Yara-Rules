rule PK_CreditDuNord_zone51 : CreditDuNord
{
    meta:
        description = "Phishing Kit impersonating Credit Du Nord bank"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2023-02-05"
        comment = "Phishing Kit - Credit Du Nord - Author: z0n51"

    strings:
        // the zipfile working on
        $local_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "espace"
        $spec_dir2 = "fin"
        $spec_dir3 = "fin_files"
        // specific files found in PhishingKit
        $spec_file = "emailconfirm-secure.php"
        $spec_file2 = "fin.html"
        $spec_file3 = "ssmsg2.php"
        $spec_file4 = "credit-du-nord.svg"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and 
	   $local_file and 
	   all of ($spec_dir*) and 
	   all of ($spec_file*)
}
