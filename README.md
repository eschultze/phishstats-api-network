## phishstats-api-network

## Visualize networks (pyvis) of phishing by querying the phishstats.info API

This code was built using python 2.7 and then changed to python 3. The only difference is the way prints are made, everything else works fine on both versions.

## Main purpose is to query phishstats.info API and create a graph network where nodes are: URL, website title, hostname, domain, IP, country, ASN (autonomous system number) and ISP. A maximum of the last 100 results are returned and used to create the network.

**PS:** the output file is a .html to be opened in a browser. If you run this tool on a server you won't be able to see the graph network.

Download `git clone https://github.com/eschultze/phishstats-api-network`

Into directory `cd phishstats-api-network/`

Install packages `pip3 install -r requirements.txt`

## Usage:
`phishapinetwork.py field operator search`

## Usage examples:
`phishapinetwork.py title eq facebook` (for phishing with title facebook)

`phishapinetwork.py title like ~facebook~` (for phishing with anything+facebook+anything)

`phishapinetwork.py ip eq 148.228.16.3` (for phishing with a specific IP address)

`phishapinetwork.py tld eq br` (for phishing with .br domains)

`phishapinetwork.py countryname eq brazil` (for phishing hosted in Brazil)

`phishapinetwork.py title asn eq as13335` (for phishing using Cloudflare)

`phishapinetwork.py title isp like ~cloudflare~` (for phishing using Cloudflare - slower than the above)

`phishapinetwork.py title like ~brandyouwanttofind~` (change it for brands you know are being targeted)

`phishapinetwork.py url like ~brandyouwanttofind~` (change it for brands you know are being targeted)

## How are the results?

![Example 1](https://phishstats.info/api-network/graph_example_1.png)

![Example 2](https://phishstats.info/api-network/graph_example_2.png)

![Example 3](https://phishstats.info/api-network/graph_example_3.png)

![Example 4](https://phishstats.info/api-network/graph_example_4.png)
