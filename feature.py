import ipaddress
import re
import urllib.request
from bs4 import BeautifulSoup
import socket
import requests
from googlesearch import search
import whois
from datetime import date, datetime
import time
from dateutil.parser import parse as date_parse
from urllib.parse import urlparse

class FeatureExtraction:
    features = []
    def __init__(self,url):
        self.features = []
        self.url = url
        self.domain = ""
        self.whois_response = ""
        self.urlparse = ""
        self.response = ""
        self.soup = ""

        try:
            self.response = requests.get(url)
            self.soup = BeautifulSoup(response.text, 'html.parser')
        except:
            pass

        try:
            self.urlparse = urlparse(url)
            self.domain = self.urlparse.netloc
        except:
            pass

        try:
            self.whois_response = whois.whois(self.domain)
        except:
            pass

        self.features.append(self.UsingIp())
        self.features.append(self.longUrl())
        self.features.append(self.shortUrl())
        self.features.append(self.symbol())
        self.features.append(self.redirecting())
        self.features.append(self.prefixSuffix())
        self.features.append(self.SubDomains())
        self.features.append(self.Hppts())
        self.features.append(self.DomainRegLen())
        self.features.append(self.Favicon())
        

        self.features.append(self.NonStdPort())
        self.features.append(self.HTTPSDomainURL())
        self.features.append(self.RequestURL())
        self.features.append(self.AnchorURL())
        self.features.append(self.LinksInScriptTags())
        self.features.append(self.ServerFormHandler())
        self.features.append(self.InfoEmail())
        self.features.append(self.AbnormalURL())
        self.features.append(self.WebsiteForwarding())
        self.features.append(self.StatusBarCust())

        self.features.append(self.DisableRightClick())
        self.features.append(self.UsingPopupWindow())
        self.features.append(self.IframeRedirection())
        self.features.append(self.AgeofDomain())
        self.features.append(self.DNSRecording())
        self.features.append(self.WebsiteTraffic())
        self.features.append(self.PageRank())
        self.features.append(self.GoogleIndex())
        self.features.append(self.LinksPointingToPage())
        self.features.append(self.StatsReport())

    # Additional feature 31: length_url
    def length_url(self):
        url_length = len(self.url)
        if url_length < 54:
            return 1
        elif 54 <= url_length <= 75:
            return 0
        else:
            return -1

    # Additional feature 32: random_domain
    def random_domain(self):
        try:
            # Assuming 'random_domain' means having a domain with random characters
            if re.search(r'\w{10,}', self.domain):
                return -1
            return 1
        except:
            return 1

    # Additional feature 33: nb_external_redirection
    def nb_external_redirection(self):
        try:
            if len(self.response.history) <= 1:
                return 1
            elif 1 < len(self.response.history) <= 4:
                return 0
            else:
                return -1
        except:
            return -1

    # Additional feature 34: suspecious_tld
    def suspecious_tld(self):
        # Assuming that checking for specific TLDs is considered suspicious
        suspicious_tlds = ['xyz', 'info', 'biz']
        for tld in suspicious_tlds:
            if tld in self.urlparse.netloc:
                return -1
        return 1

    # Additional feature 35: external_favicon
    def external_favicon(self):
        try:
            # Assuming 'external_favicon' means having a favicon from an external domain
            for link in self.soup.find_all('link', rel='icon', href=True):
                if self.url not in link['href'] and self.domain not in link['href']:
                    return -1
            return 1
        except:
            return -1

    # Additional feature 36: links_in_tags
    def links_in_tags(self):
        try:
            i, success = 0, 0
            for tag in ['a', 'img', 'audio', 'embed', 'iframe']:
                for item in self.soup.find_all(tag, src=True):
                    dots = [x.start(0) for x in re.finditer('\.', item['src'])]
                    if self.url in item['src'] or self.domain in item['src'] or len(dots) == 1:
                        success += 1
                    i += 1

            try:
                percentage = success / float(i) * 100
                if percentage < 22.0:
                    return 1
                elif 22.0 <= percentage < 61.0:
                    return 0
                else:
                    return -1
            except:
                return 0
        except:
            return -1

    # Additional feature 37: domain_in_title
    def domain_in_title(self):
        try:
            title = self.soup.title.string.lower()
            if self.domain in title:
                return 1
            return -1
        except:
            return -1

    # Additional feature 38: domain_age
    def domain_age(self):
        try:
            # Assuming 'domain_age' is the same as 'AgeofDomain' feature
            return self.AgeofDomain()
        except:
            return -1

    # Additional feature 39: web_traffic
    def web_traffic(self):
        try:
            # Assuming 'web_traffic' is the same as the existing feature
            return self.WebsiteTraffic()
        except:
            return -1

    # Additional feature 40: sfh
    def sfh(self):
        try:
            # Assuming 'sfh' means Server Form Handler and is the same as the existing feature
            return self.ServerFormHandler()
        except:
            return -1

    
    def getFeaturesList(self):
        return self.features
