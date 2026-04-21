import os
from pathlib import Path
from ripe.atlas.cousteau import AnchorRequest, ProbeRequest
import pycountry
from scapy.all import sr1
from scapy.layers.inet import IP, TCP, traceroute
import datetime
from multiprocessing import Pool
from pydantic_csv import BasemodelCSVWriter
import argparse
import signal

from tqdm import tqdm
from entites import Measure, ServerIdentity, Servers
import requests

def obtain_ripe_servers():
    for country in pycountry.countries:
        print(f"Querying anchors for {country.name}.")
        anchors = AnchorRequest(**{"country": country.alpha_2, "limit": 10})

        for anchor in anchors:
            if anchor["is_disabled"] is False:
                yield ServerIdentity(
                    id=anchor["id"],
                    country=country.alpha_2,
                    origin="RIPE",
                    ip_v4=anchor["ip_v4"],
                    ip_v6=anchor["ip_v6"]
                )

        probes = ProbeRequest(**{"country_code": country.alpha_2, "limit": 10})

        for probe in probes:
            if probe["is_public"] is True and probe["is_anchor"] is False:
                yield ServerIdentity(
                    id=probe["id"],
                    country=country.alpha_2,
                    origin="RIPE",
                    ip_v4=probe["address_v4"],
                    ip_v6=probe["address_v6"]
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
                

def read_server_source(force: bool) -> Servers:
    results = Servers()

    print("Obtaining anchors...")
    # Read from file and parse JSON
    if os.path.exists("sources.json") and not force:
        with open("sources.json", "r") as file:
            results = Servers.model_validate_json(file.read())
    else:
        for anchor in obtain_ripe_servers():
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
    """
    Return the latency in MILISECONDS
    """
    start = datetime.datetime.now()
    packet=sr1(IP(dst=destination) / TCP(dport=80, flags="S"), timeout=10, verbose=False)
    if not (packet is None):
        return (datetime.datetime.now() - start).microseconds / 1000 # from microseconds to miliseconds
    else:
        return None

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

    try:
        while(not (measures_count > max_measures or failed_attempts > max_measures)):
            single_latency = get_latency_tcp(destination)
            result, _ = traceroute(target=destination, verbose=False, dport=53, timeout=5) # is not supposed to answer on 53

            if single_latency is not None:
                latency += single_latency
                hops += len(result)
                measures_count += 1
            else:
                failed_attempts += 1
    except:
        return None

    if (measures_count > 0):
        measure = Measure(
            id=server_identity.id, 
            ground_truth=server_identity.country,
            origin=server_identity.origin,
            ip_v4=server_identity.ip_v4,
            ip_v6=server_identity.ip_v6,
            latency=round(latency / measures_count, 8), 
            hops=round(hops / measures_count, 8),
            count=measures_count
        )

        return measure
    
def remove_blank_lines(file):
    file = Path(file)
    lines = file.read_text().splitlines()
    filtered = [
        line
        for line in lines
        if line.strip()
    ]
    file.write_text('\n'.join(filtered))

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("output", help="Results output file", type=str)
    parser.add_argument("-p", "--pool", help="Number of parallel requests that will be run. Default is 16.", type=int, default=16)
    parser.add_argument("-f", "--force", help="Force reobtaining all anchors from RIPE.", action="store_true", default=False)
    parser.add_argument("-c", "--clear", help="Clear the output file from empty lines (sometimes happens idk why)", action="store_true", default=False)
    args = parser.parse_args()

    force = args.force
    pool = args.pool
    output_file = args.output
    clear = args.clear

    if clear:
        remove_blank_lines(output_file)
        exit(0)

    servers = read_server_source(force)

    i = 0
    print(f"Starting measurements on {len(servers)} servers, {pool} threads.")
    with Pool(pool, initializer=signal.signal, initargs=(signal.SIGINT, signal.SIG_IGN)) as pool, tqdm(total=len(servers)) as pbar, open(output_file, "a") as csv:
        output = []
        writer = BasemodelCSVWriter(csv, output, Measure) # would be too costly otherwise
        try:
            for measure in pool.imap(run_measurements, servers.root):
                if measure is None:
                    continue
                
                output.append(measure) # and we want to write in real-time
                writer.write(skip_header=i != 0)
                output.clear() # to avoid duplicates
                i += 1
                pbar.update()
        except KeyboardInterrupt:
            print('Measurement interrupted by user. Results may or may not have been saved.')
    

        