#############################################
# VirusTotal Public API v2.0 sample lookup.
# 
# Author: @michael_yip
# Email:  jiachongzhi@gmail.com
# Date: 08/03/2015
#############################################
import json
import urllib
from vt_util import API_KEY, load_cache, dump_cache

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
	md5 = ""
	try:
		md5 = vt_response['md5']
	except:
		return ""
	return md5
	
def get_positives(sample):
	''' Returns number of positive detections. '''
	# Get VT response
	vt_response = sample_lookup(sample)
	positives = 0
	total = 0
	scan_date = ""
	try:
		positives = vt_response['positives']
		total = vt_response['total']
		scan_date = vt_response['scan_date']
	except:
		return	0,0,""
	return positives, total, scan_date
	
def get_scans(sample):
	''' Returns scan results '''
	# Get VT response
	vt_response = sample_lookup(sample)
	scans = []
	scan_date = ""
	try:
		scans = vt_response['scans']
		scan_date = vt_response['scan_date']
	except:
		return [], ""
	return scans, scan_date

def get_permalink(sample):
	''' Returns scan results '''
	# Get VT response
	vt_response = sample_lookup(sample)
	permalink = ""
	try:
		permalink = vt_response['permalink']
	except:
		""
	return permalink