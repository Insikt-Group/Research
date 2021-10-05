import sys
import re
import json

# To Run: RedLineC2Extractor.py <path-to-RedLine-sample>
if __name__ == "__main__":
    input_file = sys.argv[1]
    print("RedLine sample filename: " + input_file)
    print("\n**************************************************\n")

    # Read in the file and search for ASCII characters encoded as UTF-16LE
    File = open(input_file, 'rb')
    file_data = File.read()
    File.close()
    pattern = re.compile(b'(?:[\x20-\x7E][\x00]){3,}')
    strings = [w.decode('utf-16le') for w in pattern.findall(file_data)]

    c2_address = ""
    build_id = ""

    # Search the strings returned from the above regex to find the C2 address, build ID, and error message (optional)
    for index, w in enumerate(strings):
        m = re.search(r'[0-9]+(?:\.[0-9]+){3}:[0-9]+',w)
        if m != None:
            c2_address = m.group(0)
            build_id = strings[index + 1]
            break

    # Check if config was found
    if (c2_address == ""):
        print("Configuration not found, sample might be obfuscated")
        quit()

    # Print the extracted information as JSON
    print("Extracted RedLine configuration\n")
    json_obj = {
        "c2_address": c2_address,
        "build_id": build_id
    }
    print(json.dumps(json_obj))

    # Write the JSON file out using the samples filename appended with "_config.json"
    with open(input_file + "_config.json", "w") as outfile:
        json.dump(json_obj, outfile)    
