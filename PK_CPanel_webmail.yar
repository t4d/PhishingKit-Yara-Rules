rule PK_CPanel_webmail : CPanel
{
    meta:
        description = "Phishing Kit impersonating CPanel"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2026-09-09"
        comment = "Phishing Kit - CPanel - CPanelWebmail phishing page"

    strings:
        // the zipfile working on
        $local_file = { 50 4b 03 04 }
        // specific files found in PhishingKit
        $spec_file1 = "config_system.php"
        $spec_file2 = "test_mail.php"
        $spec_file3 = "cpanel.svg"
        $spec_file4 = "webmail.svg"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and 
	   $local_file and 
	   all of ($spec_file*)
}
