rule PK_FedEx_ch : FedEx
{
    meta:
        description = "Phishing Kit impersonating FedEx"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-08-30"
        comment = "Phishing Kit - FedEx - 'targeting CH'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "files"
        // specific file found in PhishingKit
        $spec_file = "confirmation.html"
        $spec_file2 = "info.html"
        $spec_file3 = "sms.html"
        $spec_file4 = "tracking.png"
        $spec_file5 = "letter fedex sms.txt"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
