# Real Data Test Summary

## Scenario

Scenario 1: Solo SMB System Administrator

The tool was tested using the sample asset list and real vulnerability data files.

## Real data loaded

- CVE records loaded: 44,525
- KEV IDs loaded: 1,610
- EPSS scores loaded: 337,285
- Assets loaded: 12

## Matching result

- Raw CVE/asset matches found: 1,186

## Urgency bucket summary

- Fix today: 30
- Fix this week: 15
- Review soon: 750
- Monitor: 391

## Top affected assets

- Windows Server 2022: 715
- Google Chrome: 190
- Microsoft 365 Apps for Business: 153
- Moodle: 46
- Cisco IOS XE: 31
- Adobe Acrobat Reader DC: 25
- OpenSSL: 11
- Apache HTTP Server: 11
- Zoom: 4

## Demo conclusion

The MVP successfully loads real CVE, KEV, and EPSS data, normalises the sample asset list, matches relevant CVEs, ranks them by urgency, and exports a prioritised CSV output.

## Limitation

This MVP matches by vendor/product CPE only. It does not yet perform exact version-range checking, so some results should be reviewed manually before patching.
