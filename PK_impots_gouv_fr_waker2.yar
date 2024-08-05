rule PK_impots_gouv_fr_waker2 : impots_gouv_fr
{
    meta:
        description = "Phishing Kit impersonating impots.gouv.fr"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = "https://www.linkedin.com/feed/update/urn:li:activity:7224738166673473536/"
        date = "2024-08-05"
        comment = "Phishing Kit - impots.gouv.fr - 'IMPOT UHQ BY WAKER'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "app"
        $spec_dir1 = "server"
        $spec_dir2 = "pages"
        $spec_file1 = "opt.php"
        $spec_file2 = "4.php"
        $spec_file3 = "telepaiement_continuer.js"
        $spec_file4 = "franceConnect.js"
        $spec_file5 = "impots_gouv_fr_header-Sans fond.svg"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
