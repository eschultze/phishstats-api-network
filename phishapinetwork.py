#!/usr/bin/python3
# encoding=utf8
import json
import os
import pathlib
import requests
import sys
import webbrowser

print("Phishstats.info API Network - v0.1")

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
	params = {'_where':'('+ column +','+ compare +','+ search +')', '_fields':'url,title,host,domain,ip,countryname,asn,isp,n_times_seen_ip,n_times_seen_host,n_times_seen_domain', '_sort':'-id', '_size':'100'},
	headers = {'User-Agent':'github-network-api'}
)

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
	if new_url != "":
		g.add_node("URL-" + str(url_number), title = new_url, color = "#1ba1e2")

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
		g.add_node(new_ip, title = ("n_times_seen_ip:" + str(new_ip_times)), color = "#006699")

	if new_url != "":
		if new_ip != "":
			#if re.match (r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", new_ip):
			g.add_edge("URL-" + str(url_number), new_ip)

	new_host = entry['host']
	new_host = '{}'.format(new_host)
	if new_host != "":
		if new_host != new_ip:
			new_host_times = entry['n_times_seen_host']
			g.add_node(new_host, title = ("n_times_seen_host:" + str(new_host_times)), color = "#008080")

	if new_url != "":
		if new_host != "":
			g.add_edge("URL-" + str(url_number), new_host)

	new_domain = entry['domain']
	new_domain = '{}'.format(new_domain)
	if new_domain != "":
		if new_domain != "None":
			if new_host != new_domain:
				new_domain_times = entry['n_times_seen_domain']
				g.add_node(new_domain, title = ("n_times_seen_domain:" + str(new_domain_times)), color = "#eed514")

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