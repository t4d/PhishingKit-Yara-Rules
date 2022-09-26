rule PK_KFCU_weebee : KFCU
{
    meta:
        description = "Phishing Kit impersonating Keesler Federal Credit Union"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-08-02"
        comment = "Phishing Kit - KFCU - 'MRWEEBEE  | KEESLER FCU'"

    strings:
        // the zipfile working on
        $local_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "settings"
        $spec_dir2 = "process"
        $spec_dir3 = "ses"
        // specific files found in PhishingKit
        $spec_file = "session_emma.php"
        $spec_file2 = "78MhStYkx0gUYL4m.php"
        $spec_file3 = "ref.php"
        $spec_file4 = "verify_session_card.php"
        $spec_file5 = "MobileLogo.png"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and 
	   $local_file and 
	   all of ($spec_dir*) and 
	   all of ($spec_file*)
}