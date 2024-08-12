#!/usr/bin/python3
# encoding=utf8
import json
import os
import requests
import sys
import webbrowser
from pyvis.network import Network

def print_usage():
    print("Usage: phishapinetwork.py <column> <compare> <search> [size]")
    print("Examples:")
    print("phishapinetwork.py title eq facebook")
    print("phishapinetwork.py title like ~facebook~")
    print("phishapinetwork.py ip eq 148.228.16.3")
    print("phishapinetwork.py tld eq br")
    print("phishapinetwork.py countrycode eq br")
    print("phishapinetwork.py title asn eq as13335")
    print("phishapinetwork.py title isp like ~cloudflare~")
    print("phishapinetwork.py title like ~brandyouwanttofind~")
    print("phishapinetwork.py url like ~brandyouwanttofind~")
    exit(1)

def validate_input(args):
    if len(args) < 4 or len(args) > 5:
        print("Invalid number of arguments to make search")
        print_usage()

def fetch_data(column, compare, search, size):
    try:
        # Setting the timeout to 20 seconds
        r = requests.get(
            'https://phishstats.info:2096/api/phishing',
            params={'_where': f'({column},{compare},{search})', '_sort': '-id', '_size': size},
            headers={'User-Agent': 'github-network-api'},
            timeout=20  # Timeout set to 20 seconds
        )
        r.raise_for_status()
        return r.json(), r.elapsed.total_seconds()
    except requests.exceptions.Timeout:
        if int(size) > 10:
            print("Request timed out. Reducing size to 10 and trying again...")
            # Retry with size 10
            try:
                r = requests.get(
                    'https://phishstats.info:2096/api/phishing',
                    params={'_where': f'({column},{compare},{search})', '_sort': '-id', '_size': 10},
                    headers={'User-Agent': 'github-network-api'}
                )
                r.raise_for_status()
                return r.json(), r.elapsed.total_seconds()
            except requests.exceptions.RequestException as e:
                print(f"Error fetching data after retry: {e}")
                exit(1)
        else:
            print(f"Request timed out. No retry because size is already 10 or less.")
            exit(1)
    except requests.exceptions.RequestException as e:
        print(f"Error fetching data: {e}")
        exit(1)

def create_network_graph(data):
    g = Network(height="700px", width="1200px", bgcolor="#282a36", font_color="#f8f8f2")
    g.show_buttons(filter_=['physics'])

    url_number = 1
    for entry in data:
        add_nodes_and_edges(g, entry, url_number)
        url_number += 1

    neighbor_map = g.get_adj_list()
    for node in g.nodes:
        node["value"] = len(neighbor_map[node["id"]])

    return g

def add_nodes_and_edges(g, entry, url_number):
    new_url = entry.get('url', '')
    new_title = entry.get('title', '')
    new_ip = entry.get('ip', '')
    new_host = entry.get('host', '')
    new_domain = entry.get('domain', '')
    new_asn = entry.get('asn', '')
    new_isp = entry.get('isp', '')
    new_countryname = entry.get('countryname', '')

    if new_url:
        g.add_node(f"URL-{url_number}", title=f"{new_url}<br> HTTP code: {entry.get('http_code', '')}<br> HTTP server: {entry.get('http_server', '')}<br> Safebrowsing: {entry.get('google_safebrowsing', '')}<br> Technologies: {entry.get('technology', '')}", color="#ff79c6")

    if new_title:
        g.add_node(new_title, color="#bd93f9")
        g.add_edge(f"URL-{url_number}", new_title)

    if new_ip:
        g.add_node(new_ip, title=f"N times seen IP: {entry.get('n_times_seen_ip', '')}<br> Vulnerabilities: {entry.get('vulns', '')}<br> Ports: {entry.get('ports', '')}<br> Tags: {entry.get('tags', '')}<br> OS: {entry.get('os', '')}<br> Abuse.ch (Malware): {entry.get('abuse_ch_malware', '')}", color="#8be9fd")
        g.add_edge(f"URL-{url_number}", new_ip)

    if new_host and new_host != new_ip:
        g.add_node(new_host, title=f"N times seen Hostname: {entry.get('n_times_seen_host', '')}<br> Alexa rank: {entry.get('alexa_rank_host', '')}<br> Abuse.ch (Malware): {entry.get('abuse_ch_malware', '')}", color="#50fa7b")
        g.add_edge(f"URL-{url_number}", new_host)

    if new_domain and new_domain != "None" and new_domain != new_host:
        g.add_node(new_domain, title=f"N times seen Domain: {entry.get('n_times_seen_domain', '')}<br> Domain registered N days ago: {entry.get('domain_registered_n_days_ago', '')}<br> Alexa rank: {entry.get('alexa_rank_domain', '')}<br> Virustotal: {entry.get('virus_total', '')}<br> ThreatCrowd: {entry.get('threat_crowd', '')}<br> ThreatCrowd votes: {entry.get('threat_crowd_votes', '')}", color="#ffb86c")
        g.add_edge(new_host, new_domain)

    if new_asn:
        g.add_node(new_asn, color="#ff5555")
        g.add_edge(new_asn, new_ip)

    if new_isp:
        g.add_node(new_isp, color="#f1fa8c")
        g.add_edge(new_asn, new_isp)

    if new_countryname:
        g.add_node(new_countryname, color="#bd93f9")
        g.add_edge(new_countryname, new_isp)

def save_and_open_graph(g, column, compare, search):
    filename = f"{column}_{compare}_{search}_network.html"
    g.show(filename)
    print(f"File generated: {filename}")
    webbrowser.open(f"file://{os.getcwd()}/{filename}", new=2)

def main():
    print("Phishstats.info API Network - v0.4")
    validate_input(sys.argv)

    column, compare, search = sys.argv[1:4]
    size = sys.argv[4] if len(sys.argv) == 5 else "100"
    data, query_time = fetch_data(column, compare, search, size)

    print(f"Query took {query_time} seconds")

    if not data:
        print("Not enough data to create network")
        exit(1)

    g = create_network_graph(data)

    print(f"URLs: {len(data)}")
    print(f"Nodes: {g.num_nodes()}")
    print(f"Edges: {g.num_edges()}")

    save_and_open_graph(g, column, compare, search)

if __name__ == "__main__":
    main()
(myenv)
