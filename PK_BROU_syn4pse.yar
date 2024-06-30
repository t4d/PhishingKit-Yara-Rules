rule PK_BROU_syn4pse : BROU
{
    meta:
        description = "Phishing Kit impersonating BROU - Banco Republica"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2023-11-29"
        comment = "Phishing kit - BROU - 'C0DE BY SYN4PSE'"        

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "cerezi"
        $spec_dir2 = "movyle"
        $spec_dir3 = "jotaj"
        // specific file found in PhishingKit
        $spec_file = "crgs2.php"
        $spec_file2 = "DONDECAE.php"
        $spec_file3 = "toka3.php"
        $spec_file4 = "fns.php"
        $spec_file5 = "elfondito.jpg"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
