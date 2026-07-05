rule PK_OVHCloud_webmail : OVHCloud
{
    meta:
        description = "Phishing Kit impersonating OVH Cloud"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2026-06-20"
        comment = "Phishing Kit - OVHCloud - impersonate OVH Cloud webmail"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "assets"
        $spec_file = "connexion.php"
        $spec_file2 = "domaine-hebergement-e-mail-voip-ovh.png"
        $spec_file3 = "Logo_OVH.png"
	    $spec_file4 = "ovhcloud-logo2.png"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        // check for file
        all of ($spec_file*) and 
	    all of ($spec_dir*)
}
