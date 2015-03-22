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
from vt_util import API_KEY, load_cache, dump_cache

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
	whois_dict = {}
	try:
		# WHOIS
		whois_string = vt_response['whois']
		whois_lines = whois_string.split("\n")
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
	except:
		return {}, {}
	return whois_dict, vt_response
	
def get_registrant_email(domain):
	''' Get WHOIS registrant email. '''
	# Prettify string for VT
	if len(domain) > 0:
		domain = domain.strip().lower()
	# Get VT response
	whois_dict, vt_response = whois(domain)
	whois_timestamp = ""
	registrant_email = ""
	try:
		for k,v in whois_dict.items():
			k = k.lower().strip()
			if k.find("registrant") > -1 and k.find("email") > -1:
				registrant_email = v[0]
				break
		if 'whois_timestamp' in vt_response.keys():
			whois_timestamp = vt_response['whois_timestamp']
			whois_timestamp = __get_timestamp(whois_timestamp)
	except:
		return "",""
	if len(registrant_email) == 0:
			return ""
	return registrant_email, whois_timestamp
	
def get_name_servers(domain):
	''' Get name servers. '''
	# Get VT response
	whois_dict, vt_response = whois(domain)
	whois_timestamp = ""
	name_servers = []
	try:
		for k,v in whois_dict.items():
			k = k.lower().strip()
			if k.find("name server") > -1:
				name_servers = v
				break
		# Get WHOIS resolution timestamp
		if 'whois_timestamp' in vt_response.keys():
			whois_timestamp = vt_response['whois_timestamp']
			whois_timestamp = __get_timestamp(whois_timestamp)
	except:
		return []
	if len(name_servers) == 0:
			return [],""
	return name_servers, whois_timestamp

def get_registrar(domain):
	''' Get WHOIS registrant email. '''
	# Get VT response
	whois_dict, vt_response = whois(domain)
	registrar = ""
	whois_timestamp = ""
	try:
		for k,v in whois_dict.items():
			k = k.lower().strip()
			if k == 'registrar':
				registrar = v[0].upper()
				break
		if 'whois_timestamp' in vt_response.keys():
			whois_timestamp = vt_response['whois_timestamp']
			whois_timestamp = __get_timestamp(whois_timestamp)
	except:
		return "",""
	if len(registrar) == 0:
		return "",""
	return registrar, whois_timestamp
	
def get_subdomains(domain):
	''' Get subdomains. '''
	# Get VT response
	vt_response = domain_lookup(domain)
	subdomains = []
	try:
		subdomains = vt_response['subdomains']
	except:
		return []
	# WHOIS
	return subdomains
	
def get_ip_resolutions(domain):
	''' Get passive DNS data. '''
	# Get VT response
	vt_response = domain_lookup(domain)
	resolution_pairs = []
	try:
		resolutions = vt_response['resolutions']
		resolution_pairs = []
		for resolution in resolutions:
			resolution_pairs.append( (resolution['ip_address'], resolution['last_resolved']) )
	except:
		return []
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
	except:
		return []
	return detected_url_list

def __get_timestamp(seconds):
	''' Convert seconds into timestamp. '''
	s = seconds
	return datetime.datetime.fromtimestamp(s).strftime('%Y-%m-%d %H:%M:%S')