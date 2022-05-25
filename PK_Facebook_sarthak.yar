rule PK_Facebook_sarthak : Facebook
{
    meta:
        description = "Phishing Kit impersonating Facebook"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2020-10-29"
        comment = "Phishing Kit - Facebook - 'Username: PhishingAttack@protonmail.com Pass: @HackerSarthak'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "mobile_files"
        // specific file found in PhishingKit
        $spec_file = "mobile.html"
        $spec_file1 = "victim_ip.txt"
        $spec_file2 = "login.php"
        $spec_file3 = "login_info.txt"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        $spec_dir and 
        // check for file
        all of ($spec_file*)
}

