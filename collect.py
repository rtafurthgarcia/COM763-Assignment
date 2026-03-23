import json
import os
from typing import Iterator, Optional, Self
from pydantic import BaseModel, RootModel
from ripe.atlas.cousteau import AnchorRequest
import pycountry
from scapy.all import sr1
from scapy.layers.inet import IP, TCP, traceroute
import time
import datetime
from itertools import chain 
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

class Measure(BaseModel):
    id: int
    ground_truth: str 
    guess: Optional[str] = None
    ip_v4: Optional[str] = None
    ip_v6: Optional[str] = None
    latency: float
    hops: float
    count: int
    date_time: datetime.datetime = datetime.datetime.now()

class Measures(RootModel):
    root: list[Measure] = []

    def __iter__(self) -> Iterator[Measure]: # type: ignore
        return iter(self.root)

    def __getitem__(self, item):
        return self.root[item]
    
    def __add__(self, other: Self | list):
        if isinstance(other, Measures):
            return Measures(root=self.root + other.root)
        elif isinstance(other, list):
            return Measures(root=self.root + list(chain.from_iterable(other)))
    
    def append(self, measure: Measure):
        self.root.append(measure)

def run_measurement_for_country(couple, max_measures = 2, max_anchors = 10):
    anchors_count = 0
    country, anchors = couple
    results = []
    print(f"Starting {max_anchors} measurements for {country}.")
    for anchor in anchors:
        destination = anchor["ip_v4"] # type: ignore
        if destination is None:
            destination = anchors["ip_v6"] # type: ignore

        print(f"Taking measurements for {destination} in {country}.")
        latency = 0
        hops = 0

        measures_count = 0
        failed_attempts = 0
        while(not (measures_count > max_measures or failed_attempts > max_measures)):
            single_latency = get_latency_tcp(destination)
            result, _ = traceroute(target=destination, verbose=False, dport=53) # is not supposed to answer on 53

            if single_latency is not None:
                latency += single_latency
                hops += len(result)
                measures_count += 1
            else:
                failed_attempts += 1

        if (measures_count > 0):
            anchors_count += 1

            measure = Measure(
                id=anchor["id"],  # type: ignore
                ground_truth=country,
                ip_v4=anchor["ip_v4"], # type: ignore
                ip_v6=anchor["ip_v6"], # type: ignore
                latency=round(latency / measures_count, 8), 
                hops=round(hops / measures_count, 8),
                count=measures_count
            )

            results.append(measure)
        
        if anchors_count > max_anchors:
            break

    print(f"End of measurements for {country}.")
    return results

if __name__ == '__main__':
    anchors = obtain_anchors()

    measures = Measures()

    with Pool(4) as pool:
        measures += pool.map(run_measurement_for_country, anchors.items())

    if measures is not None and len(measures.root) > 0:
        with open("measurements.json", "w") as f:
            f.write(measures.model_dump_json()) # type: ignore

        print("Saving measurements... Done!")

