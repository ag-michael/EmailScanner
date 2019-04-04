
#!/usr/bin/python2
# -*- coding: utf-8 -*-

import logging
import elasticsearch

class ESEnrichment(object):  # Elastic seardh enrichment

    def __init__(self, logger, es_server):
        self.lh = logger
        self.es_server = es_server
    def results(self, res):
        total = []
        bl = ["adenrichment"]
        for r in res["hits"]["hits"]:
            rr = {}

            for k in r["_source"]:
                if not k in bl:
                    rr[k] = r["_source"][k]
            total.append(rr)
        return total

    def falconhosts(self, host):
        es = ES(
            {"index": "falconhosts",
             "hosts": self.es_server,
             "doctype": "falconstreaming"},
            self.lh)
        falconhostq = {
            "query": {"bool": {"must": [{"match": {"hostname": host}}]}}}
        res = es.search(falconhostq)
        if not res or 'hits' not in res:
            return []
        else:
            return self.results(res)

    def reportedphishing(self, user):
        es = ES(
            {"index": "reportedphishing",
             "hosts": self.es_server,
             "doctype": "email"},
            self.lh)
        reportedphishq = {
            "query": {"bool": {"must": [{"match": {"adenrichment.name": user}}]}}}
        res = es.search(reportedphishq)
        if not res or 'hits' not in res:
            return []
        else:
            return self.results(res)

    def fireeyedetections(self, user):
        es = ES(
            {"index": "fireeye",
             "hosts": self.es_server,
             "doctype": "email"},
            self.lh)
        fireeyeq = {
            "query": {"bool": {"must": [{"match": {"adenrichment.name": user}}]}}}
        res = es.search(fireeyeq)
        if not res or 'hits' not in res:
            return []
        else:
            return self.results(res)

    def falcondetections(self, user):
        es = ES(
            {"index": "falconstreaming-data",
             "hosts": self.es_server,
             "doctype": "falconstreaming"},
            self.lh)
        falconq = {
            "query": {"bool": {"must": [{"match": {"metadata.eventType": "DetectionSummaryEvent"}}, {"match": {"event.UserName": user}}]}}}
        res = es.search(falconq)

        if not res or 'hits' not in res:
            return []
        else:
            return self.results(res)


class ES(object):

    def __init__(self, config, logger):
        self.es = elasticsearch.Elasticsearch(hosts=config['hosts'])
        self.index_name = config['index']
        self.lh = logger
        self.doctype = config['doctype']
        #try:
            #logging.getLogger("elasticsearch").setLevel(logging.CRITICAL)
        #except BaseException:
            #self.lh.exception("Failed to set elasticsearch logger level.")

    def exists(self, docid):
        return self.es.exists(index=self.index_name,
                              doc_type=self.doctype, id=docid)

    def create(self, data, docid, ts=None):
        try:
            if not ts:
                self.es.create(index=self.index_name,
                               doc_type=self.doctype, id=docid, body=data)
            else:
                self.es.create(index=self.index_name, timestamp=ts,
                               doc_type=self.doctype, id=docid, body=data)
        except elasticsearch.ConflictError:
            self.lh.debug("Updating document "+str(docid))
            self.es.delete(
                index=self.index_name,
                doc_type=self.doctype,
                id=docid)
            self.es.create(
                index=self.index_name,
                doc_type=self.doctype,
                id=docid,
                body=data)

        except Exception as e:
            self.lh.exception('Elasticsearch create error:' + str(e))
            self.lh.debug(data)

    def search(self, query):
        try:
            return self.es.search(
                index=self.index_name, body=query, size=10000)
        except Exception as e:
            self.lh.exception('Elasticsearch search error:' + str(e))
            # print(query)

