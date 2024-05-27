rule PK_Citizens_premierghost : CitizensBank
{
    meta:
        description = "Phishing Kit impersonating Citizens Bank"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = "https://www.linkedin.com/posts/stalkphish_scama-pr0n-activity-7198548331063640064-oWAy?utm_source=share&utm_medium=member_desktop"
        date = "2024-05-27"
        comment = "Phishing Kit - CitizensBank - 'PremierGhost & Elysium'"

    strings:
        // the zipfile working on
        $local_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "Exo"
        $spec_dir2 = "Guard"
        // specific files found in PhishingKit
        $spec_file1 = "ChangeMe.ini"
        $spec_file2 = "complete.php"
        $spec_file3 = "verify.php"
        $spec_file4 = "Att.php"
        $spec_file5 = "CTZ_Green-01.png"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and 
	    $local_file and 
	    all of ($spec_dir*) and 
	    all of ($spec_file*)
}
