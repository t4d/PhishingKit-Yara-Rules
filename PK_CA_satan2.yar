rule PK_CA_satan2 : Credit_Agricole
{
    meta:
        description = "Phishing Kit impersonating Credit Agricole"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = "https://stalkphish.com/2020/12/14/how-phishing-kits-use-telegram/"
        date = "2023-04-21"
        comment = "Phishing Kit - Credit Agricole - '@Author : SATAN 2'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "inc"
        $spec_dir2 = "cache"
        $spec_dir3 = "pages"
        $spec_file1 = "authfort.php"
        $spec_file2 = "app.php"
        $spec_file3 = "region.php"
        $spec_file4 = "ca-pin.png"
        $spec_file5 = "CA_Logo_seul-1.svg"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
