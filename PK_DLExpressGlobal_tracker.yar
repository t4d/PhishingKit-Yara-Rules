rule PK_DLExpressGlobal_tracker : DLExpressGlobal
{
    meta:
        description = "Phishing Kit impersonating DL Express Global"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2023-12-01"
        comment = "Phishing Kit - DLExpressGlobal"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "global-cpanel"
        $spec_dir2 = "views"
        $spec_file1 = "ajax_index.php"
        $spec_file2 = "tracker.php"
        $spec_file3 = "manage-invoices.php"
        $spec_file4 = "testimonial.css"
    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
