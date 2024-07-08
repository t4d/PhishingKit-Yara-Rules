rule PK_VystarCU_mrweebee : VystarCU
{
    meta:
        description = "Phishing Kit impersonating VYSTAR CU"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-04-30"
        comment = "Phishing Kit - Vystar CU - 'MRWEEBEE  | VYSTAR CREDIT UNION'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "settings"
        $spec_dir2 = "Logs"
        // specific file found in PhishingKit
        $spec_file = "session_emma.php"
        $spec_file2 = "session_personal.php"
        $spec_file3 = "settings.php"
        $spec_file4 = "verify_session_emma.php"
        $spec_file5 = "Vystar_New_Logo.svg"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
