rule PK_SocieteGenerale_bikola : SocieteGenerale
{
    meta:
        description = "Phishing Kit impersonating Societe Generale"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-12-22"
        comment = "Phishing Kit - Societe Generale - 'powered by bikola'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific file found in PhishingKit
        $spec_dir = "js"
        $spec_dir1 = "img2"
        $spec_file1 = "check-sms-online-secure.html"
        $spec_file2 = "abo_adil.php"
        $spec_file3 = "sss.png"
        $spec_file4 = "clavier.js"
        $spec_file5 = "optra.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
