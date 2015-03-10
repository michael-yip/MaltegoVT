#############################################
# VirusTotal Public API v2.0 domain lookup.
# 
# Author: @michael_yip
# Email:  jiachongzhi@gmail.com
# Date: 08/03/2015
#############################################
import json
import urllib
from vt_miscellaneous import API_KEY, load_cache, dump_cache

ip_query_url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'

def ip_lookup(ip):
	''' Lookup IP information VirusTotal. '''
	# Query
	response_dict = ""
	try:
		# Check cache
		cache = load_cache(ip)
		if cache:
			return cache
			
		# Query VT
		ip_parameters = {'ip': ip, 'apikey': API_KEY}
		response = urllib.urlopen('%s?%s' % (ip_query_url, urllib.urlencode(ip_parameters))).read()
		response_dict = json.loads(response)
		
		# Cache results
		dump_cache(ip, response_dict)
	except Exception as e:
		exit(e)
	return response_dict

def get_asn(ip):
	''' Returns ASN of IP. '''
	# Get VT response
	vt_response = ip_lookup(ip)
	return vt_response['asn']
	
def get_as_owner(ip):
	''' Returns owner of AS. '''
	# Get VT response
	vt_response = ip_lookup(ip)
	return vt_response['as_owner']
	
def get_country(ip):
	''' Returns country of IP '''
	# Get VT response
	vt_response = ip_lookup(ip)
	return vt_response['country']
	
def get_domain_resolutions(ip):
	''' Returns country of IP '''
	# Get VT response
	vt_response = ip_lookup(ip)
	resolutions = vt_response['resolutions']
	resolution_pairs = []
	for resolution in resolutions:
		resolution_pairs.append( ( resolution['hostname'], resolution['last_resolved'] ) )
	return resolution_pairs

def get_detected_communicating_samples(ip):
	''' Return list of detected samples communicating to this IP. '''
	vt_response = ip_lookup(ip)
	samples = vt_response['detected_communicating_samples']
	associated_samples = []
	for sample in samples:
		associated_samples.append( ( sample['sha256'], sample['date'], sample['positives'] ) )
	return associated_samples
	
def get_detected_urls(ip):
	''' Return list of detected URLs associated with this IP. '''
	vt_response = ip_lookup(ip)
	associated_samples = []
	try:
		samples = vt_response['detected_urls']
		for sample in samples:
			associated_samples.append( ( sample['url'], sample['scan_date'] , sample['positives'] ) )
	except Exception as e:
		print e 
	return associated_samples
	
	
if __name__ == '__main__':
	ip = '85.195.82.53'
	print get_domain_resolutions(ip)