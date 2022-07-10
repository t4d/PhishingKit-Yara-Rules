rule PK_Evri_kohinq : Evri
{
    meta:
        description = "Phishing Kit impersonating Evri"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-07-10"
        comment = "Phishing Kit - Evri - 'Kohinq - NEW DATAs' - v1.32"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "remote"
        $spec_dir2 = "logs"
        // specific file found in PhishingKit
        $spec_file = "dataformat2.log"
        $spec_file2 = "track.php"
        $spec_file3 = "CONFIG.php"
        $spec_file4 = "netcraft_check.php"
        $spec_file5 = "ReferralSpamDetect.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}