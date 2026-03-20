import json
import os
from ripe.atlas.cousteau import AnchorRequest
import pycountry

def obtain_anchors():
    results: dict[str, list[AnchorRequest]] = {}

    print("Obtaining anchors...")
    # Read from file and parse JSON
    if os.path.exists("anchors.json"):
        with open("anchors.json", "r") as f:
            results = json.load(f)
    else:
        for country in pycountry.countries:
            print(f"Querying anchors for {country.name}.")
            anchors = AnchorRequest({"country": country.alpha_2, "limit": 10})

            results[country.alpha_2] = list()
            for anchor in anchors:
                if not anchor["is_disabled"]:
                    results[country.alpha_2].append(anchor)

        json_str = json.dumps(results, indent=4)
        with open("anchors.json", "w") as f:
            f.write(json_str)

    total = 0
    for country in results.values():
        total += len(country)
    print(f"{total} anchors obtained!")
    return results

print(obtain_anchors())