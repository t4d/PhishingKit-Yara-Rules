rule PK_impots_gouv_fr_x911 : impots_gouv_fr
{
    meta:
        description = "Phishing Kit impersonating impots.gouv.fr"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = "https://www.linkedin.com/posts/thdamon_phishing-activity-7471084095691886592-DoxJ"
        date = "2026-06-12"
        comment = "Phishing Kit - impots.gouv.fr - based on X911 previous kit"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "12Remboursement_files"
        $spec_dir1 = "BIRNAVA"
        $spec_dir2 = "X911"
        $spec_file1 = "TelegramApi.php"
        $spec_file2 = "chargementtt.php"
        $spec_file3 = "chargement.php"
        $spec_file4 = "passe.php"
        $spec_file5 = "dsfr.min.css"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
