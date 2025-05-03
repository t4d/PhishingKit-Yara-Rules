
PhishingKit-Yara-Rules is a [StalkPhish Project](https://stalkphish.com)

## YARA repository for Phishing Kits zip files
This repository, dedicated to Phishing Kits zip files YARA rules, is based on zip raw format analysis to find directories and files names, you don't need yara-extend there.
This repository is open to all rules contribution, feel free to create pull request with your own set of rules, sharing knowledge is the better way to improve our detection and defence against Phishing threat. 
The first set of rules has been created for the project [PhishingKit-Yara-Search](https://github.com/t4d/PhishingKit-Yara-Search).
To write your own rules you can refered to [YARA's documentation](https://yara.readthedocs.org/) or the example behind.

## Phishing Kit YARA rule example
This rule detect PayPal Phishing kit, named H3ATSTR0K3, testing for some specific files and directory presence:
```yara
rule PK_PayPal_H3ATSTR0K3 : PayPal
{
    meta:
        description = "Phishing Kit impersonating PayPal"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2019-11-28"
        comment = "Phishing Kit - PayPal - H3ATSTR0K3"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "prevents"
        // specific file found in PhishingKit
        $spec_file = "mine.php" nocase
        $spec_file2 = "bcce592108d8ec029aa75f951662de2e.jpeg"
        $spec_file3 = "captured.txt"
        $spec_file4 = "H3ATSTR0K3.txt"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        // check for file
        $spec_file and
        $spec_file2 and
        $spec_file3 and
        $spec_file4 and
        // check for directory
        $spec_dir
}
```

## Requirements
Yara is required for most of those rules to work. The better is to use the [PhishingKit-Yara-Search](https://github.com/t4d/PhishingKit-Yara-Search) project, dedicated to Phishing Kits zip files analysis.
No need of yara-extend 'cause YARA will only check for directories and files names in raw zip file format.

## Contributing
Pull requests and issues with suggestions are welcome!
See [CONTRIBUTING.md](CONTRIBUTING.md).

## Support
If you like this project, you can know buy me a coffee!

<a href="https://www.buymeacoffee.com/tad0"><img src="https://img.buymeacoffee.com/button-api/?text=Buy me a coffee&emoji=&slug=tad0&button_colour=FFDD00&font_colour=000000&font_family=Cookie&outline_colour=000000&coffee_colour=ffffff" /></a>
