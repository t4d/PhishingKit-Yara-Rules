rule PK_TelekomDE_result : TelekomDE
{
    meta:
        description = "Phishing Kit impersonating Telekom Deutschland GmbH/T-Online"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-07-09"
        comment = "Phishing Kit - Telekom DE - 'From:Result'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "index_files"
        // specific file found in PhishingKit
        $spec_file = "mail.php"
        $spec_file2 = "webauthn_1.js.download"
        $spec_file3 = "emetriq-xdn.html"
        $spec_file4 = "t-online-logo-29112019.png"
        $spec_file5 = "telekom-logo-claim.svg"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
