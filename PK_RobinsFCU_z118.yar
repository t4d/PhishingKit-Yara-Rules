rule PK_RobinsFCU_z118 : RobinsFCU
{
    meta:
        description = "Phishing Kit impersonating Robins Federal Credit Union"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-02-04"
        comment = "Phishing Kit - Robins Federal Credit Union - '$Z118_EMAIL'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "functions"
        $spec_dir2 = "grabber"
        // specific file found in PhishingKit
        $spec_file = "fullz.php"
        $spec_file2 = "CARD.php"
        $spec_file3 = "onetime.php"
        $spec_file4 = "Dila_DZ.php"
        $spec_file5 = "logo_large-e51445d8eeb9217b6aea61bb2b2af5dc.png"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
