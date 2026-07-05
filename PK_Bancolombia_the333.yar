rule PK_Bancolombia_the333 : Bancolombia
{
    meta:
        description = "Phishing Kit impersonating Bancolombia"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2026-06-1è"
        comment = "Phishing kit impersonating Bancolombia - use a 'THE333' named directory"        

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "THE333"
        $spec_dir1 = "mypaymentpendingpse_files"
        $spec_file = "mypaymentpendingpse.php"
        $spec_file2 = "pagosbancolombiauser.php"
        $spec_file3 = "phrame.php"
        $spec_file4 = "VALIDUSER.php"
        $spec_file5 = "electrico.mp3"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
