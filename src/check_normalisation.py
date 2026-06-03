from normalisation import normalise_asset_name

test_inputs = [
    "MS 365",
    "Office 365 Business",
    "Chrome Browser",
    "Apache Web Server",
    "Acrobat Reader",
    "Cisco Router IOS XE",
    "VMWare Sphere",
    "Open SSL",
    "Windows Server",
    "Wordpress CMS",
    "Moodle LMS",
    "Zoom Meetings"
]

print("NORMALISATION FUZZY TEST")
print("-" * 80)

for name in test_inputs:
    result = normalise_asset_name(name)
    print(f"{name:25} -> matched={result['matched']} | vendor={result['vendor']} | product={result['product']} | confidence={result['confidence']}")
