rule PK_CA_carg : Credit_Agricole
{
    meta:
        description = "Phishing Kit impersonating Credit Agricole"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-12-22"
        comment = "Phishing Kit - Credit Agricole - '-+ CaRg +-'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "entreeBam_fichiers"
        $spec_file0 = "att.html"
        $spec_file1 = "vrf.html"
        $spec_file2 = "fin.php"
        $spec_file3 = "mail22.php"
        $spec_file4 = "maindroit_haut.png"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
