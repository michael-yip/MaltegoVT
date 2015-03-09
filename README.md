# MaltegoVTPublic
A set of Maltego transforms for Virustotal Public API v2.0. 

This set has the added functionality of caching VT queries on a daily basis so to speed up resolutions in Maltego.

Functions available:

1) Domain:
  get_registrant_email
  get_registrar
  get_resolutions
  get_name_servers
  get_detected_urls_domain
  get_subdomains
  
2) IP:
  get_detected_communicating_samples
  get_country
  get_as_owner
  get_asn
  get_detected_urls
  
3) File (below functions are merged into one transform to enrich a given SHA256):
  get_md5
  get_scans
  get_permalink
  get_positives

= Requirement =
  +1 VirusTotal Public API key

Note: the file named 'gc' is a file "mutex" used to keep track of daily garbage collection on cached queries.
