#!/usr/bin/python2
# -*- coding: utf-8 -*-

from exchangelib.protocol import BaseProtocol, NoVerifyHTTPAdapter
from exchangelib import  Account, Credentials,Configuration
from exchangelib import FileAttachment, ItemAttachment, Message, CalendarItem, HTMLBody
from exchangelib.properties import *
from email.mime.multipart import MIMEMultipart
from urlparse import urlparse
import requests.adapters
from exchangelib.protocol import BaseProtocol
from exchangelib.ewsdatetime import EWSDateTime
from requests.auth import HTTPBasicAuth
import time
import datetime
import urllib3
import sys
import re
import json
import unidecode
import logging
import hashlib
import elasticsearch
import base64
import unicodedata
import geoip

import fireeyeformat
import phishingformat
import pymisp
from threading import Thread
from adenrichment import ADEnrichment
from elastic import ES ,ESEnrichment


def cleansmtpheader(unclean):
    prematch = re.match(r'(.*)\"smtp-header\"(.*)', unclean, re.S | re.M)
    if prematch and prematch.group(2):
        postmatch = re.findall(
            r'(^\s*\"[\w\d\-]*\":.*)',
            prematch.group(2),
            re.S | re.M)
        if postmatch:
            return prematch.group(1) + postmatch[0]
    return unclean


def unprintable(s):
    c = ''
    for i in s:
        try:
            unicode(i)
            c += i
        except BaseException:
            c += '.'
    return c


def cleanup(unclean, clean):
    i = 0
    while i < len(unclean):
        if "smtp-header" in unclean[i]:
            i += 1
            while True:
                if unclean[i].strip().startswith('"') or i >= len(unclean):
                    break
                i += 1
            continue
        clean.append(unclean[i])
        i += 1


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def parsevalues(md):
    mtype = type(md)

    if not mtype is bool and not md:
        return ""
    elif mtype is bool:
        return md

    if not mtype in [str, dict]:
        if mtype is EWSDateTime:
            md = md.strftime("%Y-%m-%dT%H:%M:%S%z")

        elif mtype is Mailbox:
            md = str(md.email_address)
        elif mtype is list:
            for i in range(0, len(md)):
                md[i] = parsevalues(md[i])
        else:
            md = str(md).encode('ascii', 'ignore').decode('ascii')
    if mtype is str:
        md = unidecode.unidecode(md)
    return md


class MailboxScanner(Thread):

    def __init__(self, conf, logger, targs=None, responders=[]):
        Thread.__init__(self)
        self.args = targs
        self.conf = conf
        self.lh = logger
        self.responders = responders
        self.feyerex = re.compile(r'^\s*([\w\-\"]*):(.*)')
        self.esenrichment = conf["esenrichment"]
        if self.esenrichment:
            self.ese = ESEnrichment(
                self.lh, self.conf["esenrichment_server"])

        if self.conf["email_alerts"]:
            from smtplib import SMTP
            from email.mime.text import MIMEText
            self.smtp = SMTP
            self.mimetext = MIMEText
        if self.conf['misp_enabled']:
            self.misp = pymisp.PyMISP(
                self.conf['mispurl'],
                self.conf['mispkey'])
        else:
            self.misp = None

        if conf["elasticsearch"]:
            if "phishing" in conf["elasticsearch_config"]:
                self.esphish = ES(
                    conf["elasticsearch_config"]["phishing"],
                    logger)
            if "fireeye" in conf["elasticsearch_config"]:
                self.esfire = ES(
                    conf["elasticsearch_config"]["fireeye"],
                    logger)
        if conf["activedirectory-enrichment"]:
            self.ad = ADEnrichment(
                conf["activedirectory-enrichment-configuration"])

        class RootCAAdapter(requests.adapters.HTTPAdapter):

            def cert_verify(self, conn, url, verify, cert):
                cert_file = conf['certs'][urlparse(url).hostname]
                super(
                    RootCAAdapter,
                    self).cert_verify(
                        conn=conn,
                        url=url,
                        verify=cert_file,
                        cert=cert)
#               BaseProtocol.HTTP_ADAPTER_CLS = RootCAAdapter

    def email_alert(self, title, emailmsg):
        if not self.conf["email_alerts"]:
            return
        notify = self.conf["email_notify"]
        server = self.conf["email_server"]
        try:
            email = self.mimetext(emailmsg, 'html')
            email['Subject'] = title
            S = self.smtp(server)
            for recipient in notify:
                S.sendmail(self.conf["email_from"],
                           recipient, email.as_string())
                self.lh.info("Sent email notification to: " + recipient)
        except Exception as e:
            self.lh.exception("Email notification exception:" + str(e))

    def mispsearch(self, value):
        if not self.misp:
            return {"item": value, "results": []}
        results = self.misp.search(values=value)
    #       print results
        if not results or not 'response' in results:
            return {"item": value, "results": []}
        else:
            #               self.lh.debug(json.dumps(results['response'],indent=4,sort_keys=True))
            return {"item": value, "results": results['response']}

    def geodict(self,name):
        res={}
        try:
            ip=socket.gethostbyname(name)
            res=geoip.geolite2.lookup(ip).get_info_dict()
        except:
            pass
        return res

    def jsonmail(self, mail, scan=False):
        md = mail.__dict__
        bl = [
            "account",
            "conversation_index",
            "reminder_is_set",
            "conversation_id",
            "changekey",
            "web_client_edit_form_query_string",
            "effective_rights",
            "item_class",
            "reminder_minutes_before_start",
            "reminder_due_by",
            "parent_folder_id",
            "attachments",
            "body",
            "unique_body",
            "text_body",
            "mime_content"]
        mbox = [
            "to_recipients",
            "sender",
            "received_representing",
            "received_by",
            "bcc_recipients",
            "author"]
        headers = md.pop("headers")
        for m in md:
            if not m in bl:
                md[m] = parsevalues(md[m])
        newheaders = {}
        if headers:
            for h in headers:
                newheaders[h.name] = h.value
        md['headers'] = newheaders

        attachmentlist = []
        if mail.has_attachments:
            for attachment in mail.attachments:
                att = {}
#                               self.lh.debug("Attachment:"+attachment.name)
                if scan and (isinstance(attachment, FileAttachment)):
                    att["name"] = attachment.name
                    att['sha256'] = sha256(attachment.content)
                    self.lh.debug("Cuckoo sumitting " + attachment.name)
                    with open("/opt/EmailScanner/tmp/" + attachment.name, "wb+") as f:
                        f.write(attachment.content)
                    try:
                        att['CuckooSubmission'] = self.cuckoosubmit(
                            "/opt/EmailScanner/tmp/" + attachment.name)
                    except BaseException:
                        self.lh.exception("CuckooSubmission Failure")

                    attachmentlist.append(att)
#                               else:
#                                       pass
# self.lh.debug(str(scan)+" Not a file, Attachment
# type:"+str(type(attachment)))
        md['attachmentinfo'] = attachmentlist
        mjson = {}
        for m in md:
            if not m in bl:
                if m.lower().strip().startswith(
                        "x-") and not m.lower().strip().startswith("x-orig"):
                    continue
                mjson[m] = md[m]
        mjson['misp'] = []
        return mjson

    def accounts(self):
        alist = []

        for m in self.conf['mailboxes']:
            try:
                credentials = Credentials(m['username'], m['password'])
                config = Configuration(
                    server=m['server'],
                    credentials=credentials)
                account = Account(
                    m['account'],
                    credentials=credentials,
                    autodiscover=m['autodiscover'],
                    config=config)
                alist.append(account)
            except Exception as e:
                self.lh.exception(
                    "Failed to load account:" + m['account'] + ":" + str(e))
                continue
        return alist

    def process_email(self, email, account, location):
        scan = False
        if location in self.conf["scannedfolders"]:
            scan = True
#               else:
#                       self.lh.debug("Not a scanned folder:"+location)
        jsonemail = self.jsonmail(email, scan=scan)
        jsonemail["location"] = location
        for responder in self.responders:
            responder(email, jsonemail)
            #self.lh.debug("Finished responder: {}".format(responder.__name__))

    def start_threads(self):
        scanners = []
        for account in self.accounts():
            scanner = MailboxScanner(
                self.conf,
                self.lh,
                targs=(True,
                       account,
                       60,
                       ),
                responders=self.responders)
            scanner.setName("Thread " + account.primary_smtp_address)
            scanner.setDaemon(True)
            scanners.append(scanner)

        for scanner in scanners:
            scanner.start()

    def run(self):
        recurse = self.args[0]  # non-recursion code was removed
        account = self.args[1]
        timer = self.args[2]
        self.lh.info("Starting thread for " + self.getName())

        while True:
            try:
                folder = account.inbox
                location = "[" + account.primary_smtp_address + "]"
                for item in folder.all().exclude(categories__icontains='Processed').order_by(
                        '-datetime_received')[:1000]:  # folder.all().order_by('-datetime_received')[:100]:
                    self.process_email(item, account, location)
                    if not isinstance(item.categories, list):
                        item.categories = ["Processed"]
                    else:
                        item.categories.append("Processed")
                    item.save()

                for folder in account.inbox.walk():
                    location = "[" + account.primary_smtp_address + "]"
                    tmpfolder = folder
                    tree = []
                    while tmpfolder.parent:
                        tree.insert(0, tmpfolder.name)
                        tmpfolder = tmpfolder.parent
                        if not tmpfolder.parent:
                            del tree[0]
                            tree.insert(0, "root")
                    location = location + ".".join(tree)
                    location = location.rstrip(".")
                    self.lh.debug("Scanning " + location)
                    for item in folder.all().exclude(categories__icontains='Processed').order_by(
                            '-datetime_received')[:1000]:  # folder.all().order_by('-datetime_received')[:100]:
                        self.process_email(item, account, location)
                        if not isinstance(item.categories, list):
                            item.categories = ["Processed"]
                        else:
                            item.categories.append("Processed")
                        item.save()
                        time.sleep(2)

                time.sleep(timer)
            except Exception as e:
                self.lh.exception(str(e))
                time.sleep(5)
                continue

    def addresponder(self, responder):  # A responder is just a "processor"
        self.responders.append(responder)

    def esindexresponder(self,mail,jsonemail):
        if jsonemail['location'] in self.conf['folders_indexed']:
            ts = jsonemail["datetime_received"]
            try:
                self.esphish.create(json.dumps(jsonemail), mail.id, ts=ts)
            except Exception:
                self.lh.exception("Index document creation failure")
            self.lh.info("esindexresponder: Updated Elasticsearch index for email: Subject:{} from: {}".format(jsonemail['subject'],jsonemail['sender']) )
        else:
            self.lh.debug("esindexresponder: Skipping email: Location(folder):{} Subject:{} from: {}".format(jsonemail['location'],jsonemail['subject'],jsonemail['sender']) )
    def geoipresponder(self,mail,jsonemail):
        if 'm' in jsonemail:
            try:
                senderdomain=jsonemail['m']['sender'].split('@')[1]
                jsonemail['SenderCountry']=self.geodict(senderdomain)
            except:
                self.lh.exception("Failed to set SenderCountry")
                jsonemail['SenderCountry']={}
            self.lh.debug("GeoIP responder finished for email: Subject:{} from: {}".format(jsonemail['subject'],jsonemail['sender']) )

    def esphishingresponder(self, mail, jsonemail):
        if not jsonemail["location"] in self.conf["phishingemailfolders"]:
            return
        if jsonemail["received_by"].lower(
        ) != self.conf["phishing_report_address"]:
            return
        exists = self.esphish.exists(mail.id)
        if jsonemail["received_by"].lower(
        ) == self.conf["phishing_report_address"]:
            try:
                self.phishingalert(mail, jsonemail)
            except BaseException:
                self.lh.exception("Phishing alert error,trying unparsed")
                try:
                    self.phishingalert(mail, jsonemail, parsefailure=True)
                except BaseException:
                    self.lh.exception("Failed to create a phishing alert")
#                if not "Processed" in jsonnemail["categories"]:
        if jsonemail["location"] in self.conf['phishingemailfolders']:
            phishingformat.phishingformat(
                mail, jsonemail, self.lh, self.conf)
        else:
            self.lh.debug(
                "Not formatting:" +
                mail.subject +
                " - location:" +
                jsonemail[
                    "location"])
            self.lh.debug("esphishingresponder: finished for email: Subject:{} from: {}".format(jsonemail['subject'],jsonemail['sender']) )

    def phishingartifacts(self, mail, jsonemail):
        '''[{"dataType":"mail","data":alert["alert"]["src"]["smtp-mail-from"],"message":"email sender"},
                        {"dataType":"domain","data":alert["alert"]["src"]["domain"],"message":"sender domain"},
                        {"dataType":"url","data":alert["alert"]["src"]["url"],"message":"detected url"},
                        {"dataType":"mail","data":alert["alert"]["dst"]["smtp-to"],"message":"recipient"}

            ]
        '''
        artifacts = []
        observables = {
            "File Name": "filename",
            "Computer Name": "hostname",
            "IP Address": "ip",
            "From": "mail",
            "To": "mail",
            "Subject": "mail_subject",
            "x-originating-ip": "ip",
            "SHA256": "hash",
            "MD5": "hash",
            "URL": "url",
            "URL Domain": "domain"}
        try:
            if "m" in jsonemail:
                if "sender" in jsonemail["m"]:
                    artifacts.append(
                        {"dataType": "mail",
                         "data": jsonemail["m"]["sender"],
                            "message": "email sender"})
                    jsonemail['misp'].append(
                        self.mispsearch(jsonemail["m"]["sender"]))
                if "received_by" in jsonemail["m"]:
                    artifacts.append(
                        {"dataType": "mail",
                         "data": jsonemail["m"]["received_by"],
                            "message": "email recipient"})
                if "attachmentinfo" in jsonemail["m"]:
                    for attachment in jsonemail["m"]["attachmentinfo"]:
                        artifacts.append(
                            {"dataType": "hash",
                             "data": attachment["sha256"],
                                "message": "email attachment hash"})
                        jsonemail['misp'].append(
                            self.mispsearch(attachment["sha256"]))
                domainsfound = set()

                for attachment in mail.attachments:
                    if isinstance(attachment, ItemAttachment) and isinstance(
                            attachment.item, Message):
                        for ln in attachment.item.body:
                            urls = re.findall(
                                r"(\w{0,6}:\/\/[^\s\'\"<>]*)",
                                ln)
                            urls += re.findall(
                                r"href=[\"\']([^\s\'\"<>]*)",
                                ln)
                            for i in range(0, len(urls)):
                                if urls[i].lower().startswith("href="):
                                    urls[i] = urls[6:]

                            url = list(set(urls))
                            if urls:
                                for url in urls:
                                    url = url.replace(
                                        "[",
                                        "").replace("]",
                                                    "").replace("hxxp",
                                                                "http").strip()
                                    artifacts.append(
                                        {"dataType": "url",
                                         "data": url,
                                         "message": "URL"})
                                    domain = ''
                                    dmatch = re.match(
                                        r"\w{0,6}:\/\/([\w\d\.\-]*)",
                                        url)
                                    if dmatch and not None is dmatch.group(
                                            1):
                                        domainsfound.add(dmatch.group(1))
                            #                       print url
                        #                       else:
                            #                       print url
            domainsfound = set()

            for o in observables:
                if not mail.text_body:
                    continue
                for ln in mail.text_body.splitlines():
                    m = re.match("^" + o + r':\s*(.*)', ln.strip())
                    # print mail.text_body
                    if not None is m and not None is m.group(1):
                        artifacts.append(
                            {"dataType": observables[o],
                             "data": m.group(1).replace("[",
                                                        "").replace("]",
                                                                    "").strip(),
                                "message": "Phishing email submission artifact"})
                        if ln.strip().lower().startswith("url"):
                            dmatch = re.match(
                                r"\w{0,6}:\/\/([\w\d\.\-]*)",
                                m.group(1).replace("[",
                                                   "").replace("]",
                                                               "").strip().replace("hxxp",
                                                                                   "http"))
                            if dmatch and not None is dmatch.group(1):
                                domainsfound.add(dmatch.group(1))
                            #       print url
                            # else:
                                # print url

            for domain in domainsfound:
                artifacts.append(
                    {"dataType": "domain",
                     "data": domain,
                     "message": "domain"})
                jsonemail['misp'].append(self.mispsearch(domain))

        except BaseException:
            self.lh.exception("Phishing artifact parsing failure")
        return artifacts

    def phishingalert(self, mail, jsonemail, parsefailure=False):
        if not jsonemail["location"] in self.conf["phishingemailfolders"]:
            return
        if self.esenrichment and "adenrichment" in jsonemail and "name" in jsonemail[
                "adenrichment"]:
            jsonemail["FalconDetections"] = self.ese.falcondetections(
                jsonemail["adenrichment"]["name"])
            jsonemail["FireEyeDetections"] = self.ese.fireeyedetections(
                jsonemail["adenrichment"]["name"])
        title = "Phishing Email Submission:" + mail.subject
        sev = 2
        artifacts = []
        if not parsefailure:
            artifacts = self.phishingartifacts(mail, jsonemail)
            thehivealert = {
                "title": title,
                "description": "```\n" +
                phishingformat.phishingformatmd(jsonemail, mail) + "\n```",
                "type": "Spear Phishing",
                "sourceRef": jsonemail["id"],
                "source": "ExchangeScanner",
                "severity": sev,
                "tlp": 3,
                "artifacts": artifacts,
                "caseTemplate": "Phishing email"
            }

        else:
            thehivealert = {
                "title": title,
                "description": "```\n" + mail.text_body + "\n```",
                "type": "Spear Phishing",
                "sourceRef": jsonemail["id"],
                "source": "ExchangeScanner",
                "severity": sev,
                "tlp": 3,
                "artifacts": artifacts,
                "caseTemplate": "Phishing email"
            }

        self.thehive_alert(thehivealert)
        self.lh.info("Created thehive phishing alert:" + title)

    def esfireeyeparsefailure(self, mail, jsonemail):
        try:
            if "retroactive" in mail.body.lower():
                alert = {
                    "alert": unprintable(
                        mail.body),
                    "error": "parsefailure"}
                self.email_alert(
                    mail.subject,
                    fireeyeformat.fireeyeformat(alert))
                if not isinstance(mail.categories, list):
                    mail.categories = ['Parsefailure']
                else:
                    mail.categories.append("Parsefailure")
                mail.is_read = True
                mail.save()

        except BaseException:
            self.lh.exception("fireeye parse failure")

    def esfireeyeresponder(self, mail, jsonemail):
        kv = {}
        if jsonemail["sender"].lower() == self.conf["fireeyeaddress"]:
            try:

                id = sha256(mail.body)
                mbody = mail.body

                cleaned = []
                cleanup(mbody.splitlines(), cleaned)

                try:
                    kv = json.loads(' '.join(cleaned), strict=False)
                except BaseException:
                    try:
                        kv = json.loads(mbody, strict=False)
                    except BaseException:
                        try:
                            clean = cleansmtpheader(mbody)
                            kv = json.loads(clean, strict=False)
                        except BaseException:
                            self.esfireeyeparsefailure(mail, jsonemail)
                            return

                product = kv["product"]
                fresh = True
                if not self.esfire.exists(id) and product == "Email MPS":
                    kv["adenrichment"] = self.ad.adlookup(
                        kv["alert"]["dst"]["smtp-to"], "mail")
                    fresh = True
                self.esfire.create(json.dumps(kv), id)
                if "src" in kv["alert"]:
                    if "url" in kv["alert"]["src"]:
                        url = kv["alert"]["src"]["url"].strip()
                        if url.lower().startswith("hxxp"):
                            url = url.replace('hxxp', 'http')
                            dmatch = re.match(
                                r"\w{0,6}:\/\/([\w\d\.\-]*)",
                                url)
                            if dmatch and dmatch.group(1):
                                domain = dmatch.group(1)
                                with open("whitelist-domains.txt") as f:
                                    for ln in f.read().splitlines():
                                        if domain.lower() == ln.strip():
                                            domain = ''
                                            self.lh.debug(
                                                "Whitelisted domain detected by FireEye")
                                            break
                                if domain:
                                    self.lh.info(
                                        "FireEye detected a malicious domain:" +
                                        domain)
                                    malware = ""
                                    try:
                                        malware = kv[
                                            "alert"][
                                                "explanation"][
                                                    "malware-detected"][
                                                        "malware"][
                                                            "name"]
                                    except BaseException:
                                        pass
                                    desc = "FireEye detected a malicious URL '" + \
                                        url + "' for :" + malware
                                    try:
                                        self.falconcustomioc(
                                            domain,
                                            'domain',
                                            desc,
                                            "EmailScanner:" + desc)
                                    except BaseException:
                                        self.lh.exception(
                                            "Falcon custom IOC creation error for url:" +
                                            url)
                                    try:
                                        self.feyemisp(
                                            kv["alert"],
                                            desc,
                                            domain,
                                            url)
                                    except BaseException:
                                        self.lh.exception(
                                            "FireEye URL match MISP event creation error for url:" +
                                            url)
                if fresh and product == "Email MPS" and "explanation" in kv["alert"]:
                    # print kv["alert"]["explanation"]
                    stype = ''
                    try:
                        stype = kv[
                            "alert"][
                                "explanation"][
                                    "malware-detected"][
                                        "malware"][
                                            "stype"]
                    except BaseException:
                        pass
                    if stype == "retroactive":
                        kv["adenrichment"] = self.ad.adlookup(
                            kv["alert"]["dst"]["smtp-to"], "mail")
                        self.fireeyealert(mail, kv)
                if not isinstance(mail.categories, list):
                    mail.categories = ['Processed']
                else:
                    mail.categories.append("Processed")
                mail.is_read = True
                mail.save()
            except Exception as e:
                self.lh.exception(str(e))
                self.lh.debug(mail.body)

    def adenrichmentresponder(self, mail, jsonemail):
        if self.esphish.exists(mail.id):
            return
        jsonemail["adenrichment"] = self.ad.adlookup(
            jsonemail["sender"], "mail")

    def msgresponder(self, mail, jsonemail):
        if mail.attachments:
            attachmentcount = 0
            for attachment in mail.attachments:
                if isinstance(attachment, ItemAttachment) and isinstance(
                        attachment.item, Message):
                    if attachmentcount == 0:
                        jsonemail["m"] = self.jsonmail(
                            attachment.item, scan=True)
                    else:
                        jsonemail["m-" + str(attachmentcount)] = self.jsonmail(
                            attachment.item, scan=True)
                attachmentcount += 1

    def falconcustomioc(self, ioc, ioctype, desc, source):
        if not self.conf['falcon_customioc']:
            return
        postdata = json.dumps(
            [{"type": ioctype,
              "value": ioc.strip(),
              "policy": "detect",
              "description": desc[:180],
              "share_level": "red",
                             "source": source[:180],
                             "expiration_days": 60}])
        response = requests.post(
            self.conf['falconapi_url'],
            data=postdata,
            headers={"Content-Type": "application/json"},
            auth=HTTPBasicAuth(self.conf['falconapi_user'],
                               self.conf['falconapi_key']))
        json_response = json.loads(response.text)
        if json_response["errors"]:
            self.lh.error(str(json_response["errors"]))
            return
        else:
            self.lh.info(
                ioc +
                " Submitted to Crowdstrike Falcon custom IOC api")

    def feyemisp(self, alert, desc="FireEye alert", domain=None, url=None):
        if not self.misp or (not domain and not url):
            return
        ev = pymisp.MISPEvent()
        desc = unprintable(desc).strip()

        event_template = '{"orgc_id": "1", "info": "' + desc + \
            '", "event_creator_email": "emailscanner@emailscanner.local", "locked": false, "Object": [], "Tag": [{"name": "FireEye"}, {"name": "EmailScanner"}], "Galaxy": [], "published": false, "distribution": "1", "proposal_email_lock": false, "threat_level_id": "2", "RelatedEvent": []}'
        att = []

        if domain:
            att.append(
                {"category": "Network activity",
                 "to_ids": True,
                 "type": "domain",
                 "value": domain,
                 "comment": desc})
        if url:
            att.append(
                {"category": "Network activity",
                 "to_ids": True,
                 "type": "url",
                 "value": url,
                 "comment": desc})
        event_json = json.loads(event_template)
        event_json["Attribute"] = att
        ev.from_json(json.dumps(event_json))

        self.misp.add_event(ev)

    def fireeyealert(self, mail, alert):
        if self.esenrichment and "adenrichment" in alert and "name" in alert["adenrichment"]:
            alert["FalconDetections"] = self.ese.falcondetections(
                alert["adenrichment"]["name"])
            alert["ReportedPhishing"] = self.ese.reportedphishing(
                alert["adenrichment"]["name"])

        try:
            url = alert["alert"]["src"]["url"].strip()
            if url.startswith("http"):
                alert["CuckooSubmissions"] = [
                    cuckoosubmit(url, analysis="url")]
        except BaseException:
            self.lh.exception("FireEye URL Cuckoosubmission failure")
        try:
            self.fireeye_thehive(mail, alert)
        except BaseException:
            self.lh.exception("FireEye-Thehive")
            print(alert)
        self.email_alert(mail.subject, fireeyeformat.fireeyeformat(alert))

    def thehive_alert(self, alert):
        authheader = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' +
            self.conf[
                'thehiveapi']}
        res = requests.post(
            self.conf["thehive-url"],
            headers=authheader,
            data=json.dumps(alert),
            verify=False)
#               self.lh.debug("DEBUG Thehive alert result:"+res.text)

    def fireeye_thehive(self, mail, alert, parsefail=False):
        title = "FireEye EX Retroactive detection:" + mail.subject
        sev = 3
        tags = ["FireEye"]
        thehivealert = {}
        if not parsefail:
            try:
                malware = alert[
                    "alert"][
                        "explanation"][
                            "malware-detected"][
                                "malware"]
                tags.append(malware["name"])
                tags.append(malware["stype"])
            except BaseException:
                pass
            thehivealert = {
                "title": title,
                "description": "```\n" +
                fireeyeformat.fireeyeformatmd(alert) + "\n```",
                "type": "Spear Phishing",
                "sourceRef": alert["alert"]["alert-url"],
                "source": "EmailScanner",
                "severity": sev,
                "tlp": 3,
                "artifacts": [{"dataType": "mail", "data": alert["alert"]["src"]["smtp-mail-from"], "message":"email sender"},
                              {"dataType": "domain", "data": alert["alert"][
                               "src"]["domain"], "message":"sender domain"},
                              {"dataType": "url", "data": alert["alert"][
                               "src"]["url"], "message":"detected url"},
                              {"dataType": "mail", "data": alert["alert"][
                               "dst"]["smtp-to"], "message":"recipient"}

                              ],
                "caseTemplate": "Phishing email",
                "tags": tags
            }
        else:
            thehivealert = {
                "title": title,
                "description": "```\n" +
                json.dumps(alert, sort_keys=true, indent=4) + "\n```",
                "type": "Spear Phishing",
                "sourceRef": "FireEye EX",
                "source": "EmailScanner",
                "severity": sev,
                "tlp": 3,
                "artifacts": [],
                "caseTemplate": "Phishing email",
                "tags": tags
            }

        self.thehive_alert(thehivealert)
        self.lh.info("Created thehivelert:" + title)

    def uniquesubmission(self, sample):
        #               return True
        with open("/opt/EmailScanner/submissions.txt") as f:
            for ln in f.read().splitlines():
                if ln == sample.lower().strip():
                    return False
        return True

    def cuckoosubmit(self, fname, custom="", analysis="file", name=""):
        response = ''
        for ext in self.conf["cuckoowhitelist"]:
            if fname.lower().endswith(ext.lower()):
                self.lh.debug(
                    "CuckooSubmit: Whitelisted extension for " +
                    fname)
                return None
        json_response = {}
        try:

            if analysis == "file":
                fh = ''
                with open(fname) as f:
                    fh = sha256(f.read())
                if not self.uniquesubmission(fh):
                    return
                else:
                    with open("/opt/EmailScanner/submissions.txt", "a+") as f:
                        f.write(str(fh) + "\n")
                with open(fname, "rb") as malware:
                    posturl = self.conf["cuckooapi"] + "/tasks/create/file"
                    nm = fname
                    if name:
                        nm = name
                    response = requests.post(
                        posturl,
                        files={'file': (nm,
                                        malware),
                               "machine": "cuckoosandbox",
                               "options": "unique,free=yes",
                               "unique": "yes"})
                if response:
                    # print(response.text)
                    json_response = json.loads(response.text)
                    if json_response and 'task_id' in json_response:
                        aurl = self.conf["cuckooweb"] + "/analysis/" + str(
                            json_response['task_id'])
                        json_response["url"] = aurl
                        self.lh.debug("Analysis URL: " + aurl)

                else:
                    self.lh.error("NO cuckoo response")
            elif analysis == "url" and 'http' in fname.lower() and uniquesubmission(fname):
                posturl = self.conf["cuckooapi"] + "/tasks/create/url"
                data = {
                    "url": fname.strip(
                    ),
                    "machine": "cuckoosandbox",
                    "options": "unique,free=yes",
                    "unique": "yes",
                    "free": "yes",
                    "owner": "EmailScanner",
                    "tags": [
                        "EmailScanner"]}
                response = requests.post(posturl, data=data)
                if response:
                    with open("submissions.txt", "a+") as f:
                        f.write(fname.lower() + "\n")
                    json_response = json.loads(response.text)
                    if json_response and 'task_id' in json_response:
                        aurl = self.conf["cuckooweb"] + "/analysis/" + str(
                            json_response['task_id'])
                        json_response["url"] = aurl
                        self.lh.debug("Analysis URL: " + aurl)

        except Exception:
            self.lh.exception("CuckooSubmission")
            return json_response
        return json_response


def main():
    reload(sys)
    sys.setdefaultencoding('utf8')
    urllib3.disable_warnings()
    logging.basicConfig(format='EmailScanner: %(asctime)-15s  %(message)s')
    lh = logging.getLogger('EmailScanner')
    lh.setLevel(logging.DEBUG)
    BaseProtocol.HTTP_ADAPTER_CLS = NoVerifyHTTPAdapter
    configuration = None

    with open("emailscanner.json") as f:
        configuration = json.loads(f.read())
    if not configuration:
        lh.error("Unable to load configuration file")
        lh.exception("Configuration file error")
        sys.exit(1)
    ms = MailboxScanner(configuration, lh)
    '''
        This allows for extending the service by simply adding more responders
        "responders" are processed in order. In the code below, adenrichmentresponder processes the email before msgresponder
        '''
    ms.addresponder(ms.adenrichmentresponder)
    ms.addresponder(ms.msgresponder)
    ms.addresponder(ms.geoipresponder)
    ms.addresponder(ms.esindexresponder)
    ms.addresponder(ms.esphishingresponder)
    ms.addresponder(ms.esfireeyeresponder)
    ms.start_threads()
    while True:
        time.sleep(1)


if __name__ == '__main__':
    main()
