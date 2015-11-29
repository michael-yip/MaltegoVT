# MaltegoVT
A set of Maltego transforms for Virustotal Public API v2.0. 

This set has the added functionality of caching VT queries on a daily basis so to speed up resolutions in Maltego.  

Functions available:  

1) Domain:  
  get_registrant_email  
  get_registrar  
  get_ip_resolutions    
  get_name_servers  
  get_detected_urls_domain  
  get_subdomains  
  
2) IP:  
  get_detected_communicating_samples  
  get_country  
  get_as_owner  
  get_asn  
  get_domain_resolutions  
  get_detected_urls  
  get_domain_resolutions  
  
3) File (below functions are merged into one transform to enrich a given SHA256):  
  get_md5  
  get_scans  
  get_permalink  
  get_positives  

= Requirement =  
  + VirusTotal Public API key

= Installation (using the Maltego configuration file) =  
  1) Place content from this reposition in the path C:/Maltego Transforms/MaltegoVTPublic/  
  2) Open Maltego and import the configuration file named "MaltegoVTPub.mtz"  
  3) Place your VirusTotal API key in vt_util.py

Note 1: the file named 'gc' is a file "mutex" used to keep track of daily garbage collection on cached queries.
Note 2: the provided Maltego configuration file assumes Windows as the underlying operating system. For Linux, simply go to "Manage transforms" in Maltego and change to Linux path notations for the transforms to work.

If you have any problems, message me on Twitter: https://twitter.com/michael_yip :-)
