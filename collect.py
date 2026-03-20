import json
import os
from ripe.atlas.cousteau import AnchorRequest
import pycountry
from scapy.all import sr1
from scapy.layers.inet import IP, UDP, ICMP
import time
import datetime
from dataclasses import dataclass

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

# https://www.geeksforgeeks.org/linux-unix/traceroute-implementation-on-python/
def traceroute(destination: str, max_hops=30, timeout=2) -> int:
    port = 33434
    ttl = 1

    while True:
        # Creating the IP and UDP headers
        ip_packet = IP(dst=destination, ttl=ttl)
        udp_packet = UDP(dport=port)

        # Combining the headers
        packet = ip_packet / udp_packet

        # Sending the packet and receive a reply
        reply = sr1(packet, timeout=timeout, verbose=0)

        if reply is None:
            # No reply, print * for timeout
            print(f"{ttl}\t")
        elif reply.type == 3:
            # Destination reached, print the details
            print(f"{ttl}\t{reply.src}")
            break
        else:
            # Printing the IP address of the intermediate hop
            print(f"{ttl}\t{reply.src}")

        ttl += 1

        if ttl > max_hops:
            break
    
    return ttl

def ping(destination: str, timeout=2) -> float | None:
    packet = IP(dst=destination, ttl=20)/ICMP()
    reply = sr1(packet, timeout=timeout)
    start = time.time()
    if not (reply is None):
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

anchors = obtain_anchors()

results = list()
max_measurements = 3
for country, anchors in anchors.items():
    count = 0
    for anchor in anchors:
        both_measures = False

        destination = anchor["ip_v4"] # type: ignore
        if destination is None:
            destination = anchors["ip_v6"] # type: ignore

        latency = None
        hops = 0

        for i in (1, max_measurements):
            single_latency = ping(destination)
            single_hops = traceroute(destination)

            if single_latency is not None:
                latency = 0
                latency += single_latency

            hops += single_hops

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
        
        if count > 10:
            break