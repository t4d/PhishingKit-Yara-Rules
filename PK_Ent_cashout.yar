rule PK_Ent_cashout : Ent
{
    meta:
        description = "Phishing Kit impersonating Ent Online Banking"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2023-07-10"
        comment = "Phishing Kit - Ent - 'From: Cashout-XXX'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "Citadel FCU_files"
        $spec_dir2 = "Log In Ent Online Banking_files"
        $spec_dir3 = "OnPoint Community Credit Union_files"
        $spec_file1 = "algo.php"
        $spec_file2 = "Verif.php"
        $spec_file4 = "Cancel.php"
        $spec_file5 = "Email (1).php"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
