rule PK_NavyFederal_venza : NavyFederal
{
    meta:
        description = "Phishing Kit impersonating Navy Federal Credit Union"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-10-10"
        comment = "Phishing Kit - Navy Federal - 'CrEaTeD bY VeNzA'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "images"
        $spec_dir2 = "includes"
        // specific file found in PhishingKit
        $spec_file = "quest.php"
        $spec_file2 = "account.php"
        $spec_file3 = "email.php"
        $spec_file4 = "next.php"
        $spec_file5 = "NFCU_Mob_Logo-1d62888b4b662af9142e3c385f423f32.svg"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
