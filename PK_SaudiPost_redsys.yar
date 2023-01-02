rule PK_SaudiPost_redsys : SaudiPost
{
    meta:
        description = "Phishing Kit impersonating Saudi Post | SPL"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2023-01-01"
        comment = "Phishing Kit - Saudi Post - using Redsys files"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "Ilion"
        $spec_dir2 = "Venta_fichiers"
        $spec_dir3 = "Redsys_files"
        $spec_file1 = "Redsys.php"
        $spec_file2 = "pp.php"
        $spec_file3 = "third-loading.php"
        $spec_file4 = "telegram.php"
        $spec_file5 = "POST.svg"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
