#############################################
# VirusTotal Public API v2.0 domain lookup.
# 
# Author: @michael_yip
# Email:  jiachongzhi@gmail.com
# Date: 08/03/2015
#############################################
import json
import urllib
import datetime
from vt_miscellaneous import API_KEY, load_cache, dump_cache

domain_query_url = 'https://www.virustotal.com/vtapi/v2/domain/report'

def domain_lookup(domain):
	''' Lookup domain information VirusTotal. '''
	# Query
	response_dict = ""
	try:
		# Check cache
		cache = load_cache(domain)
		if cache:
			return cache
		
		# Query VT
		domain_parameters = {'domain': domain, 'apikey': API_KEY}
		response = urllib.urlopen('%s?%s' % (domain_query_url, urllib.urlencode(domain_parameters))).read()
		response_dict = json.loads(response)
		
		# Cache results
		dump_cache(domain, response_dict)
	except Exception as e:
		exit(e)
	return response_dict
	
def whois(domain):
	''' WHOIS Lookup.
		NOTE: this returns the original JSON reponse from VT to save query.
	'''
	# Get VT response
	vt_response = domain_lookup(domain)
	
	# WHOIS
	whois_string = vt_response['whois']
	whois_lines = whois_string.split("\n")
	whois_dict = {}
	for line in whois_lines:
		if line.find(":") > -1:
			line_s = line.split(":")
			k = line_s[0].strip()
			v = line_s[1].strip()
			if k in whois_dict.keys():
				values = whois_dict[k]
				values.append(v)
				whois_dict[k] = values
			else:
				whois_dict[k] = [v]
	return whois_dict, vt_response
	
def get_registrant_email(domain):
	''' Get WHOIS registrant email. '''
	
	# Get VT response
	whois_dict, vt_response = whois(domain)

	registrant_email = ""
	for k,v in whois_dict.items():
		k = k.lower().strip()
		if k.find("registrant") > -1 and k.find("email") > -1:
			registrant_email = v[0]
			break
	whois_timestamp = vt_response['whois_timestamp']
	if len(registrant_email) == 0:
		return ""
	return registrant_email, __get_timestamp(whois_timestamp)
	
def get_name_servers(domain):
	''' Get name servers. '''
	# Get VT response
	whois_dict, vt_response = whois(domain)

	name_servers = []
	for k,v in whois_dict.items():
		k = k.lower().strip()
		if k.find("name server") > -1:
			name_servers = v
			break
	whois_timestamp = vt_response['whois_timestamp']
	if len(name_servers) == 0:
		return []
	return name_servers, __get_timestamp(whois_timestamp)

def get_registrar(domain):
	''' Get WHOIS registrant email. '''
	# Get VT response
	whois_dict, vt_response = whois(domain)
	registrar = ""
	for k,v in whois_dict.items():
		k = k.lower().strip()
		if k == 'registrar':
			registrar = v[0].upper()
			break
	whois_timestamp = vt_response['whois_timestamp']
	if len(registrar) == 0:
		return ""
	return registrar, __get_timestamp(whois_timestamp)
	
def get_subdomains(domain):
	''' Get subdomains. '''
	# Get VT response
	vt_response = domain_lookup(domain)
	# WHOIS
	return vt_response['subdomains']
	
def get_ip_resolutions(domain):
	''' Get passive DNS data. '''
	# Get VT response
	vt_response = domain_lookup(domain)
	resolutions = vt_response['resolutions']
	resolution_pairs = []
	for resolution in resolutions:
		resolution_pairs.append( (resolution['ip_address'], resolution['last_resolved']) )
	return resolution_pairs
	
def get_detected_urls_domain(domain):
	''' Get detected urls. '''
	# Get VT response
	vt_response = domain_lookup(domain)
	detected_url_list = []
	try:
		detected_urls = vt_response['detected_urls']
		
		for detected_url in detected_urls:
			detected_url_list.append( (detected_url['url'], detected_url['scan_date'], detected_url['positives']) )
	except Exception as e:
		pass
	return detected_url_list

def __get_timestamp(seconds):
	''' Convert seconds into timestamp. '''
	s = seconds
	return datetime.datetime.fromtimestamp(s).strftime('%Y-%m-%d %H:%M:%S')

	
