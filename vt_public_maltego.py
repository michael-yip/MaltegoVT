#############################################
# VirusTotal Public API Maltego transform.
# 
# Author: @michael_yip
# Email:  jiachongzhi@gmail.com
# Date: 08/03/2015
#############################################

from vt_domain import whois, get_registrant_email, get_registrar, get_ip_resolutions, get_detected_urls_domain, get_name_servers, get_subdomains
from vt_ip import get_asn, get_as_owner, get_country, get_detected_communicating_samples, get_detected_urls, get_domain_resolutions
from vt_file import get_positives, get_permalink, get_scans, get_md5
from MaltegoTransform import * 
import sys 

# IP
def query_ip(query, ip):
	''' Query VT for information on IP. '''
	me.addUIMessage("[INFO] Querying for IP: %s." % ip)
	return {
				'get_detected_communicating_samples' : ('samples', get_detected_communicating_samples(ip)),
				'get_country' : ( 'location', get_country(ip) ),
				'get_as_owner' : ('as_owner', get_as_owner(ip)),
				'get_asn' : ('as', get_asn(ip)),
				'get_detected_urls' : ('urls', get_detected_urls(ip)),
				'get_resolutions'	:  ('domains', get_domain_resolutions(ip))
			}[query]
			
# Domain
def query_domain(query, domain):
	''' Query VT for information on IP. '''
	me.addUIMessage("[INFO] Querying for domain: %s." % domain)
	return {
				'get_registrant_email' : ('email', get_registrant_email(domain)),
				'get_registrar' : ('registrar', get_registrar(domain)),
				'get_resolutions' : ('ip', get_ip_resolutions(domain)),
				'get_name_servers' : ('ns', get_name_servers(domain)),
				'get_detected_urls' : ('urls', get_detected_urls_domain(domain)),
				'get_subdomains': ('subdomains', get_subdomains(domain)),
			}[query]
			
# File
def query_file(sha256):
	''' Query extra data for a given file SHA256. '''
	me.addUIMessage("[INFO] Querying for file: %s." % sha256)
	# Get MD5
	m_obj = me.addEntity("malformity.Hash", get_md5(sha256))
	scans, timestamp = get_scans(sha256)
	# Get Scan date
	m_obj.addAdditionalFields('Scan date', 'Scan date', False, timestamp)
	# Get Permalink
	permalink = get_permalink(sha256)
	m_obj.addAdditionalFields('Permalink', 'Permalink', False, permalink)
	positives, total, scan_date = get_positives(sha256)
	# AV Detections
	m_obj.addAdditionalFields('Detection', 'AV detection rate', False, "%d out of %d" % (positives, total))
	# Scan results
	for k, v in scans.items():
		v = dict(v)
		if v['detected'] == True:
			m_obj.addAdditionalFields(k, k, False, "%s [%s]" % (v['result'], v['version'] ))
	
def to_entity(query_result):
	''' Convert values from IP and domain queries to Maltego entity.'''
	# Unpack
	entity_type, values = query_result
	
	# No value - return none
	if len(values) == 0: 
		me.addUIMessage("[INFO] No new entities found.")
		return None
	
	
	# Hash
	if entity_type == "samples":
		for sample, scan_date, positives in values:
			me.addEntity("malformity.Hash", sample)
			
	# URL
	if entity_type == "urls":
		for url, scan_date, positives in values:
			me.addEntity("maltego.Website", str(url))

	# IP
	if entity_type == "ip":
		ips = values
		for ip, timesamp in values:
			me.addEntity("maltego.IPv4Address", ip)

	# Name server
	if entity_type == "ns":
		name_servers, timestamp = values
		for name_server in name_servers:
			me.addEntity("maltego.NSRecord", name_server)
	
	# Domains
	if entity_type == "domains":
		for website in values:
			me.addEntity("maltego.Domain", website)
			
	# Subdomains
	if entity_type == "subdomains":
		for website in values:
			me.addEntity("maltego.Website", website)

	# Location
	if entity_type == "location":
		me.addEntity("maltego.Location", values)
		
	# AS Owner
	if entity_type == "as_owner":
		me.addEntity("maltego.Alias", values)
		
	# Registrar
	if entity_type == "registrar":
		registrar, timestamp = values
		me.addEntity("maltego.Alias", registrar)
	# AS
	if entity_type == "as":
		me.addEntity("maltego.AS", values)
		
	# Email
	if entity_type == "email":
		email, timestamp = values
		me.addEntity("maltego.EmailAddress", email)
		
if __name__ == "__main__":
	# Type of entity (1=IP, 2=Domain, 3=File)
	entity_type = sys.argv[1]
	query = ""
	value = ""
	if entity_type == 'ip' or entity_type == 'domain':
		# Query
		query = sys.argv[2]
		# Entity value
		value = sys.argv[3] 
	else:
		# Entity value
		value = sys.argv[2] 
		
	# Maltego Transform object
	me = MaltegoTransform() 
	
	me.addUIMessage("[INFO] Querying...")
	me.addUIMessage("[INFO] Entity type: %s..." % entity_type)
	me.addUIMessage("[INFO] Query: %s..." % query)
	me.addUIMessage("[INFO] Value: %s..." % value)
	
	# To Maltego entity
	if entity_type == 'ip':
		to_entity(query_ip(query, value))
	elif entity_type == 'domain':
		to_entity(query_domain(query, value))
	elif entity_type == 'file':
		query_file(value)
	me.returnOutput()