rule PK_ESL_sigmadev : ESL_FCU
{
    meta:
        description = "Phishing Kit impersonating ESL Federal Credit Union"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-01-15"
        comment = "Phishing Kit - ESL-FCU - '-[ SIGMADEV - END ]-'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir1 = "config"
        $spec_dir2 = "emailauth"
        $spec_file1 = "question.php"
        $spec_file2 = "outlook.php"
        $spec_file3 = "vld.php"
        $spec_file4 = "signon_clean.css"
        $spec_file5 = "equal-housing-lender.svg"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
