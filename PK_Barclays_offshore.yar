rule PK_Barclays_offshore : Barclays
{
    meta:
        description = "Phishing Kit impersonating Barclays"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = "https://www.stalkphish.com"
        date = "2024-11-18"
        comment = "Phishing Kit - Barclays - 'from: info@barclayoffshoreservice.com'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "Barclays"
        $spec_dir2 = "investment-banking"
        $spec_dir3 = "research"
        $spec_file = "investment-banking.html"
        $spec_file2 = "prologin.php"
        $spec_file3 = "forget.html"
	    $spec_file4 = "confirm.php"
        $spec_file5 = "58DC32B2-F657-40B2-8875-7A66293E8278.jpeg"
        $spec_file6 = "dashboard-e-commerce.png"
        $spec_file7 = "barclays-logo-mobile.svg"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and 
        all of ($spec_dir*) and 
        all of ($spec_file*)
}
