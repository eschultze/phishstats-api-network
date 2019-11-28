#!/usr/bin/python3
# encoding=utf8
import json
import os
import pathlib
import requests
import sys
import webbrowser

print("Phishstats.info API Network - v0.2")

#Cheking for arguments
if len(sys.argv) <= 3:
	print("Not enough arguments to make search")
	exit(1)

column = sys.argv[1]
compare = sys.argv[2]
search = sys.argv[3]

#Making the API request
r = requests.get(
	'https://phishstats.info:2096/api/phishing',
	params = {'_where':'('+ column +','+ compare +','+ search +')', '_sort':'-id', '_size':'100'},
	headers = {'User-Agent':'github-network-api'}
)

#Print the request URL
#print(r.url)

#Loading the output as json
output = json.loads(r.text)

print ("Query took " + str(r.elapsed.total_seconds()) + " seconds")

url_counter = 0
for url in output:
	url_counter += 1

#Cheking for data
if url_counter <= 0:
	print("Not enough data to create network")
	exit(1)

from pyvis.network import Network

#Parameters for pyvis network
g = Network(height="700px", width="700px", bgcolor="#718487", font_color="white")

#Uncomment below to force a specific algorithm
#g.barnes_hut()
#g.force_atlas_2based()

#Comment below if you don't want physics options on the final html
g.show_buttons(filter_=['physics'])

url_number = 1

for entry in output:

	new_url = entry['url']
	new_url = '{}'.format(new_url)
	new_url_http_code = entry['http_code']
	new_url_http_server = entry['http_server']
	new_url_safebrowsing = entry['google_safebrowsing']
	if new_url != "":
		g.add_node("URL-" + str(url_number), title = (new_url + "<br> HTTP code: " + str(new_url_http_code) + "<br> HTTP server: " + str(new_url_http_server) + "<br> Safebrowsing: " + str(new_url_safebrowsing)), color = "#1ba1e2")

	new_title = entry['title']
	new_title = '{}'.format(new_title)
	if new_title != "":
		g.add_node(new_title, color = "#2eaf57")

	if new_url != "":
		if new_title != "":
			g.add_edge("URL-" + str(url_number), new_title)

	new_ip = entry['ip']
	new_ip = '{}'.format(new_ip)

	if new_ip != "":
		new_ip_times = entry['n_times_seen_ip']
		new_ip_vulns = entry['vulns']
		new_ip_ports = entry['ports']
		new_ip_tags = entry['tags']
		new_ip_os = entry['os']
		new_ip_abusech = entry['abuse_ch_malware']
		g.add_node(new_ip, title = ("N times seen IP: " + str(new_ip_times) + "<br> Vulnerabilities: " + str(new_ip_vulns) + "<br> Ports: " + str(new_ip_ports) + "<br> Tags: " + str(new_ip_tags) + "<br> OS: " + str(new_ip_os) + "<br> Abuse.ch (Malware): " + str(new_ip_abusech)), color = "#006699")

	if new_url != "":
		if new_ip != "":
			#if re.match (r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", new_ip):
			g.add_edge("URL-" + str(url_number), new_ip)

	new_host = entry['host']
	new_host = '{}'.format(new_host)
	if new_host != "":
		if new_host != new_ip:
			new_host_times = entry['n_times_seen_host']
			new_host_alexa = entry['alexa_rank_host']
			new_host_abusech = entry['abuse_ch_malware']
			g.add_node(new_host, title = ("N times seen Hostname: " + str(new_host_times) + "<br> Alexa rank: " + str(new_host_alexa) + "<br> Abuse.ch (Malware): " + str(new_host_abusech)), color = "#008080")

	if new_url != "":
		if new_host != "":
			g.add_edge("URL-" + str(url_number), new_host)

	new_domain = entry['domain']
	new_domain = '{}'.format(new_domain)
	if new_domain != "":
		if new_domain != "None":
			if new_host != new_domain:
				new_domain_times = entry['n_times_seen_domain']
				new_domain_days_ago = entry['domain_registered_n_days_ago']
				new_domain_alexa = entry['alexa_rank_domain']
				new_domain_virustotal = entry['virus_total']
				new_domain_threat_crowd = entry['threat_crowd']
				new_domain_threat_crowd_votes = entry['threat_crowd_votes']
				g.add_node(new_domain, title = ("N times seen Domain: " + str(new_domain_times) + "<br> Domain registered N days ago: " + str(new_domain_days_ago) + "<br> Alexa rank: " + str(new_domain_alexa) + "<br> Virustotal: " + str(new_domain_virustotal) + "<br> ThreatCrowd: " + str(new_domain_threat_crowd) + "<br> ThreatCrowd votes: " + str(new_domain_threat_crowd_votes)), color = "#eed514")

	if new_domain != "":
		if new_host != "":
			if new_domain != "None":
				if new_domain != new_host:
					g.add_edge(new_host, new_domain)

	new_asn = entry['asn']
	new_asn = '{}'.format(new_asn)
	if new_asn != "":
		g.add_node(new_asn, color = "#db870e")

	if new_asn != "":
		if new_ip != "":
			g.add_edge(new_asn, new_ip)

	new_isp = entry['isp']
	new_isp = '{}'.format(new_isp)
	if new_isp != "":
		g.add_node(new_isp, color = "#7969a9")

	if new_isp != "":
		if new_asn != "":
			g.add_edge(new_asn, new_isp)

	new_countryname = entry['countryname']
	new_countryname = '{}'.format(new_countryname)
	if new_countryname != "":
		g.add_node(new_countryname, color = "#39af8e")

	if new_countryname != "":
		if new_isp != "":
			g.add_edge(new_countryname, new_isp)

	url_number += 1

#Checking for size/value of nodes
neighbor_map = g.get_adj_list()
for node in g.nodes:
	node["value"] = len(neighbor_map[node["id"]])

print("URLs: " + str(url_counter))
print("Nodes: " + str(g.num_nodes()))
print("Edges: " + str(g.num_edges()))

#g.show("network.html")
g.show(column + "_" + compare + "_" + search + "_network.html")
print("File generated: " + column + "_" + compare + "_" + search + "_network.html")

#If you don't want to automatically open the current html file in your browser comment the 3 lines below
new_tab = 2
file = "file://" + os.getcwd() + "/" + column + "_" + compare + "_" + search + "_network.html"
webbrowser.open(file,new=new_tab)
