import os
from ripe.atlas.cousteau import AnchorRequest
import pycountry
from scapy.all import sr1
from scapy.layers.inet import IP, TCP, traceroute
import time
from multiprocessing import Pool
from pydantic_csv import BasemodelCSVReader, BasemodelCSVWriter

from tqdm import tqdm
from entites import Measure, ServerIdentity, Servers
import requests

def obtain_ripe_anchors():
    for country in pycountry.countries:
        print(f"Querying anchors for {country.name}.")
        anchors = AnchorRequest(**{"country": country.alpha_2, "limit": 10})

        for anchor in anchors:
            if not anchor["is_disabled"]:
                yield ServerIdentity(
                    id=anchor["id"],
                    country=country.alpha_2,
                    origin="RIPE",
                    ip_v4=anchor["ip_v4"],
                    ip_v6=anchor["ip_v6"]
                )

def obtain_mullvad_vpns():
    print(f"Querying mullvad servers.")
    response = requests.get("https://api.mullvad.net/www/relays/all/")
    servers_list = response.json()

    for i, server in enumerate(servers_list):
        if server["active"] is True:
            yield ServerIdentity(
                origin="Mullvad",
                id=i,
                country=server["country_code"],
                ip_v4=server["ipv4_addr_in"],
                ip_v6=server["ipv6_addr_in"]
            )

def obtain_nordvpn_vpns():
    print(f"Querying NordVPN servers.")
    response = requests.get("https://api.nordvpn.com/v1/servers?limit=0")
    servers_list = response.json()

    for server in servers_list:
        if server["status"] == "online":
            yield ServerIdentity(
                origin="NordVPN",
                id=server["id"],
                country=server["locations"][0]["country"]["code"],
                ip_v4=server["station"],
                ip_v6=server["ipv6_station"]
            )
                

def read_server_source() -> Servers:
    results = Servers()

    print("Obtaining anchors...")
    # Read from file and parse JSON
    if os.path.exists("sources.json"):
        with open("sources.json", "r") as file:
            results = Servers.model_validate_json(file.read())
    else:
        for anchor in obtain_ripe_anchors():
            results.add(anchor)

        for server in obtain_mullvad_vpns():
            results.add(server)

        for server in obtain_nordvpn_vpns():
            results.add(server)

        with open("sources.json", "w") as file:
            file.write(results.model_dump_json())

    total = len(results)
    print(f"{total} anchors obtained!")
    return results

def get_latency_tcp(destination: str) -> float | None:
    packet=sr1(IP(dst=destination) / TCP(dport=80, flags="S"), timeout=10, verbose=False)
    start = time.time()
    if not (packet is None):
        return time.time() - start
    else:
        return 0

def run_measurements(server_identity: ServerIdentity, max_measures = 3):
    destination = server_identity.ip_v4
    if destination is None:
        destination = server_identity.ip_v6
    if destination is None:
        return

    latency = 0
    hops = 0

    measures_count = 0
    failed_attempts = 0
    while(not (measures_count > max_measures or failed_attempts > max_measures)):
        single_latency = get_latency_tcp(destination)
        result, _ = traceroute(target=destination, verbose=False, dport=53, timeout=5) # is not supposed to answer on 53

        if single_latency is not None:
            latency += single_latency
            hops += len(result)
            measures_count += 1
        else:
            failed_attempts += 1

    if (measures_count > 0):
        measure = Measure(
            id=server_identity.id, 
            ground_truth=server_identity.country,
            origin=server_identity.origin,
            ip_v4=server_identity.ip_v4,
            ip_v6=server_identity.ip_v6,
            latency=round(latency / measures_count, 8), 
            hops=round(hops / measures_count),
            count=measures_count
        )

        #print(f"{measure.origin}:{destination} from {measure.ground_truth} replied in avg {measure.latency}ms in {measure.hops} hops.")

        return measure

if __name__ == '__main__':
    servers = read_server_source()

    i = 0
    print(f"Starting measurements on {len(servers)} servers.")
    with Pool(16) as pool, tqdm(total=len(servers)) as pbar, open("output.csv", "a") as csv:
        output = []
        writer = BasemodelCSVWriter(csv, output, Measure) # would be too costly otherwise
        for measure in pool.imap(run_measurements, servers.root):
            if measure is None:
                continue
            
            output.append(measure) # and we want to write in real-time
            writer.write(skip_header=i != 0)
            output.clear() # to avoid duplicates
            i += 1
            pbar.update()