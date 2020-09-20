#######################################################################
# Copyright (c) 2020
# Boussad AIT SALEM <boussad.aitsalem<at>gmail<dot>com>
# All rights reserved.
########################################################################
#
#  This file is part of msdn plugin of IDA PRO
#
#  MSDN_IDAPRO is free software: you can redistribute it and/or modify it
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

from idaapi import *
from idautils import * 
from subprocess import Popen
import httplib, urllib2,webbrowser

import ida_kernwin



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


def hotkey_pressed():
    search = None

    for xref in XrefsFrom(here(), 0):

        if xref.type == fl_CN or xref.type == fl_CF:
            search = Name(xref.to)

    if search:
            search = getOnlineMsdnContent(search)
            webbrowser.open(search)
    else:
    	    print "FAILED: Nothing found to search."



try:
    hotkey_ctx
    if ida_kernwin.del_hotkey(hotkey_ctx):
        print("Hotkey unregistered!")
        del hotkey_ctx
    else:
        print("Failed to delete hotkey!")
except:
    hotkey_ctx = ida_kernwin.add_hotkey("Shift-H", hotkey_pressed)
    if hotkey_ctx is None:
        print("Failed to register hotkey!")
        del hotkey_ctx
    else:
        print("Hotkey registered!")


