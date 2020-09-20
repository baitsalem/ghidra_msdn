#######################################################################
# Copyright (c) 2020
# Boussad AIT SALEM <boussad.aitsalem<at>gmail<dot>com>
# All rights reserved.
########################################################################
#
#  This file is part of msdn plugin of GHIDRA
#
#  MSDN_GHIDRA is free software: you can redistribute it and/or modify it
#  under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful, but
#  WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#  General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see
#  <http://www.gnu.org/licenses/>.
#
########################################################################

# @author B. AIT SALEM 
# @category _NEW_
# @keybinding Shift-H 
# @menupath Tools.MSDN.view_documentation
# @toolbar 


DEFAULT_BROWSER='firefox'

#GOOGLE_SEARCH_PREFIX = "https://www.google.com/search?btnI&q="
#DUCKDUCKGO_SEARCH_PREFIX = "https://duckduckgo.com/?q=!ducky "
#SEARCH_PREFIX = GOOGLE_SEARCH_PREFIX

from subprocess import Popen
from ghidra.program.model.symbol import FlowType
import httplib, urllib2
import webbrowser



def _getFirstMsdnLink(feed_content):
        """
        Parses the first MSDN URL from a RSS feed.
        @param feed_content: a rss feed output
        @type feed_content: str
        @return: (str) the first MSDN url if existing.
        """
        while feed_content.find("<link>") > -1:
            start_index = feed_content.find("<link>")
            end_index = feed_content.find("</link>")
            link_url = feed_content[len("<link>") + start_index:end_index]
            #print(link_url)            
            if "docs.microsoft.com" in link_url:
                return link_url
            else:
                feed_content = feed_content[feed_content.find("</link>") + 7:]
            return ""



def download(url):
        """
        Start a blocking download. Will return the downloaded content when done.
        @param url: The URL to download from.
        @type url: str
        @return: (str) the downloaded content.
        """
        # print "Downloader.download(): type of received parameter: ", type(url)
        host = url[8:url.find("/", 8)]
        path = url[url.find("/", 8):]
        
        print ( "host : {}".format(host)) 
        print ( "path : {}".format(path)) 


        try:
            conn = httplib.HTTPSConnection(host)
            conn.request("GET", path)
            response = conn.getresponse()
            if response.status == 200:
                print "[+] Downloaded from: %s" % (url)
                _data = response.read()
            else:
                print "[-] Download failed: %s (%s %s)" % (url, response.status, response.reason)
                _data = "Download failed (%s %s)!" % (response.status, response.reason)
            conn.close()
        except Exception as exc:
            print ("[!] Downloader.download: Exception while downloading: %s" % exc)
            _data = None
        return _data




def getOnlineMsdnContent(keyword):
        """
        This functions downloads content from the MSDN website. Return the first valid result
        @param keyword: the keyword to look up in MSDN
        @type keyword: str
        @return: (str) a waiting message if the keyword has been queried or a negative answer if
            there are no entries in MSDN
        """
        feed_url = "https://social.msdn.microsoft.com/search/en-US/feed?format=RSS&query=%s" % keyword
        feed_content = download(feed_url)
        if not feed_content:
            return "<p>Could not access the MSDN feed. Check your Internet connection.</p>"
        msdn_url = _getFirstMsdnLink(feed_content)
        
        if msdn_url != "":
            #print("Download : {}".format(msdn_url))
            return msdn_url
        else:
            return "<p>Even MSDN can't help you on this one.</p>"



def search_address(address):
	search = None
	f = getFunctionAt(address)
	if f:
		search = f.getName()
		if search.startswith("FID_conflict:"):
			search = search[13:]
	return search

search = None

for r in getReferencesFrom(currentAddress):
	if r.isExternalReference():
		search = r.getLabel()
		#search = r.getLibraryName() + " " + r.getLabel()
                break
	t = r.getReferenceType()
	if t == FlowType.UNCONDITIONAL_CALL:
		search = search_address(r.getToAddress())
		if search:
			break

if search == None:
	search = search_address(currentAddress)

if search:
	#search = SEARCH_PREFIX + search
        search = getOnlineMsdnContent(search)
        #webbrowser.open(search)
	Popen([DEFAULT_BROWSER, search])
else:
	print "FAILED: Nothing found to search."
