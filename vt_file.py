#############################################
# VirusTotal Public API v2.0 sample lookup.
# 
# Author: @michael_yip
# Email:  jiachongzhi@gmail.com
# Date: 08/03/2015
#############################################
import json
import urllib
from vt_miscellaneous import API_KEY, load_cache, dump_cache

file_url = "https://www.virustotal.com/vtapi/v2/file/report"


def sample_lookup(hash):
	# Query
	response_dict = ""
	try:
		# Check cache
		cache = load_cache(hash)
		if cache:
			return cache
			
		# Query VT
		hash_parameters = {'resource': hash, 'apikey': API_KEY}
		response = urllib.urlopen('%s?%s' % (file_url, urllib.urlencode(hash_parameters))).read()
		response_dict = json.loads(response)
		
		# Cache results
		dump_cache(hash, response_dict)
	except Exception as e:
		exit(e)
	return response_dict

def get_md5(sample):
	''' Returns MD5 of sample. '''
	# Get VT response
	vt_response = sample_lookup(sample)
	return vt_response['md5']
	
def get_positives(sample):
	''' Returns number of positive detections. '''
	# Get VT response
	vt_response = sample_lookup(sample)
	return vt_response['positives'], vt_response['total'], vt_response['scan_date']
	
def get_scans(sample):
	''' Returns scan results '''
	# Get VT response
	vt_response = sample_lookup(sample)
	#"scans": {"nProtect": {"detected": true, "version": "2010-05-14.01", "result": "Trojan.Generic.3611249", "update": "20100514"},}
	return vt_response['scans'], vt_response['scan_date']

def get_permalink(sample):
	''' Returns scan results '''
	# Get VT response
	vt_response = sample_lookup(sample)
	return vt_response['permalink']
