from functools import partial
import json
import os
from ripe.atlas.cousteau import AnchorRequest
import pycountry
from scapy.all import sr, sr1
from scapy.layers.inet import IP, TCP, UDP, ICMP, traceroute
import time
import datetime
from dataclasses import dataclass
from multiprocessing import Pool

def obtain_anchors() -> dict[str, list[AnchorRequest]]:
    results: dict[str, list[AnchorRequest]] = {}

    print("Obtaining anchors...")
    # Read from file and parse JSON
    if os.path.exists("anchors.json"):
        with open("anchors.json", "r") as f:
            results = json.load(f)
    else:
        for country in pycountry.countries:
            print(f"Querying anchors for {country.name}.")
            anchors = AnchorRequest(**{"country": country.alpha_2, "limit": 10})

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

def get_latency_tcp(destination: str) -> float | None:
    packet=sr1(IP(dst=destination) / TCP(dport=80, flags="S"), timeout=10, verbose=False)
    start = time.time()
    if not (packet is None):
        return time.time() - start
    else:
        return 0

@dataclass
class Measure:
    id: int
    ground_truth: str 
    ip_v4: str
    ip_v6: str
    latency: float
    hops: float
    guess: str = ""
    date_time: datetime.datetime = datetime.datetime.now()

def run_measurement_for_country(couple, max_measurements = 2, max_anchors = 10):
    count = 0
    country, anchors = couple
    results: list[Measure] = []
    print(f"Starting {max_anchors} measurements for {country}.")
    for anchor in anchors:
        destination = anchor["ip_v4"] # type: ignore
        if destination is None:
            destination = anchors["ip_v6"] # type: ignore

        print(f"Taking measurements for {destination} in {country}.")
        latency = None
        hops = 0

        for i in (0, max_measurements):
            single_latency = get_latency_tcp(destination)
            # is a tcp syn traceroute
            result, _ = traceroute(target=destination, verbose=False, dport=53) # is not supposed to answer on 53

            if single_latency is not None:
                latency = 0
                latency += single_latency

            hops += len(result)

        if (latency is not None and hops > 0):
            count += 1

            measure = Measure(
                id=["id"],  # type: ignore
                ground_truth=country,
                ip_v4=anchor["ip_v4"], # type: ignore
                ip_v6=anchor["ip_v6"], # type: ignore
                latency=latency / max_measurements, 
                hops=hops / max_measurements
            )

            results.append(measure)
        
        if count > max_anchors:
            break

    print(f"End of measurements for {country}.")
    return results


if __name__ == '__main__':
    anchors = obtain_anchors()

    results = list()
    max_measurements = 3

    with Pool(4) as pool:
        results = pool.map(run_measurement_for_country, anchors.items())
    final_results = [
        x
        for xs in results
        for x in xs
    ]

    json_str = json.dumps(results, indent=4)
    with open("measurements.json", "w") as f:
        f.write(json_str)

    print("Saving measurements... Done!")

