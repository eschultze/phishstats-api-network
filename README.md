## phishstats-api-network

## Visualize networks of phishing by querying phishstats.info API

Changelog

v0.1 - Initial release.

v0.2 - Shodan integration.

v0.3 - Technologies used to build the website/phishing.

v0.4 - Enhanced error handling, added dynamic timeout management and support for optional input parameters.

## Overview

The **PhishStats API Network** tool allows users to visualize phishing networks by querying the [phishstats.info](https://phishstats.info) API. It generates an interactive graph network using the `pyvis` library, where nodes represent key elements like URLs, website titles, hostnames, domains, IP addresses, countries, Autonomous System Numbers (ASNs), and Internet Service Providers (ISPs). The tool processes up to the last 100 phishing incidents to build these networks.

**Please note**: The generated output is an HTML file designed to be viewed in a browser. If you run this tool on a headless server, you might not be able to view the network graph directly.

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

`phishapinetwork.py countrycode eq br` (for phishing hosted in Brazil)

`phishapinetwork.py title asn eq as13335` (for phishing using Cloudflare)

`phishapinetwork.py title isp like ~cloudflare~` (for phishing using Cloudflare - slower than the above)

`phishapinetwork.py title like ~brandyouwanttofind~` (change it for brands you know are being targeted)

`phishapinetwork.py url like ~brandyouwanttofind~` (change it for brands you know are being targeted)

## How is the output?

![Example 1](https://phishstats.info/graph_example_1.png)
