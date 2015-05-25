#############################################
# VirusTotal Public API v2.0 miscellaneous 
# functions.
# 
# Author: @michael_yip
# Email:  jiachongzhi@gmail.com
# Date: 08/03/2015
#############################################
from os import getcwd, listdir
from os.path import isfile, join, getmtime
from datetime import datetime, timedelta
import pickle
import md5

# API KEY
API_KEY = '<INSERT YOUR VirusTotal Public API KEY HERE>'

# Cache directory
CACHE_DIR = 'cache'
CACHE_PATH = join(getcwd(), CACHE_DIR)

def is_modified_today(filepath):
	''' Check if cache was modified today. '''
	modfied_time = getmtime(filepath)
	return (datetime.today() - datetime.fromtimestamp(modfied_time)) < timedelta(days = 1)

def load_cache(term):
	# Garbage collect
	garbage_collect()
	''' Check if a term has already been searched.'''
	term = md5.new(term).hexdigest()
	# List files in cache directory
	try:
		cache_files = [ f for f in listdir(CACHE_PATH) if isfile(join(CACHE_PATH, f)) ]
		if term in cache_files:
			# If cache exists, if it was made today:
			if is_modified_today(join(CACHE_PATH,term)):
				with open(join(CACHE_PATH,term), 'rb') as cache_file:
					return pickle.load(cache_file)
	except Exception as e:
		pass
	return None
	
def garbage_collect():
	''' Clear cache. '''
	# Check garbage collect mutex if it was modified today
	try:
		if is_modified_today('gc'): 
			return
		cache_files = [ f for f in listdir(CACHE_PATH) if isfile(join(CACHE_PATH, f)) ]
		for cache_file in cache_files:
			path_to_file = join(CACHE_PATH, cache_file)
			if not is_modified_today(path_to_file):
				remove(path_to_file)
		# Touch garbage collect mutex
		open('gc', 'a').close()
	except:
		open('gc', 'a').close()

def dump_cache(term, json):
	''' Cache VT result for the given term. '''
	term = md5.new(term).hexdigest()
	try:
		with open(join(CACHE_PATH,term), 'wb') as cache_file:
				pickle.dump(json, cache_file)
				return True
	except Exception as e:
		pass
	return False