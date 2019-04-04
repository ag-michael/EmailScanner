import json
import traceback
import html as h


def dicttable(j, html, prepend=None, cell='cell'):
    for k in j:
        html += "<tr>"
        key = k
        if prepend:
            key = prepend + k
        try:
            if not isinstance(j[k], dict):
                html += "<td id='key' class='" + cell + "'>" + key + \
                    "</td><td id='value' class='" + cell + \
                        "'>" + h.escape(str(j[k])) + "</td>"
            else:
                html += "<td id='key' class='" + cell + "'>" + key
                html += "</td><td id='value' class='" + cell + "'><pre>" + \
                    h.escape(
                        json.dumps(
                            j[k],
                            sort_keys=True,
                            indent=4)) + "</pre></td>"
        except BaseException:
            print j
            traceback.print_exc()
            raise
        html += "</tr>"
    return html


def misprow(value, conf):
    if not value["results"]:
        return ""
    for r in value["results"]:
        r = r["Event"]
        h = "<tr><td id='misp'>" + value['item'] + "</td>"
        h += "<td id='misp'>" + r['date'] + "</td>"
        h += "<td id='misp'><a href='" + \
            conf['mispui'] + "/events/view/" + \
            r['id'] + "'>" + r['info'] + "</a></td>"
        h += "<td id='misp'>"
        if not 'Tag' in r:
            r['Tag'] = []
        for tag in r['Tag']:
            h += "<span id='tag' style='background-color:" + \
                tag['colour'] + ";'>" + tag['name'] + "</span>"

        h += "</td><td id='misp'>" + str(r['attribute_count']) + "</td>"
        h += "</tr>"

    h += "</tr>"
    return h


def phishingformat(mail, j, lh, conf):
    if not "m" in j:
        return
    lh.debug("Email analysis formatting started for:" + mail.subject)
    style = None
    with open("phishing.css") as f:
        style = "<style>\n"
        style += f.read()
        style += "\n</style>"

    feye = falcon = misp = []
    phish = adinfo = falconhost = {}
    mispfound = False
    try:
        if "FalconDetections" in j:
            falcon = j.pop("FalconDetections")
        if "FireEyeDetections" in j:
            feye = j.pop("FireEyeDetections")
        if "adenrichment" in j:
            adinfo = j.pop("adenrichment")
        if "m" in j:
            phish = j.pop("m")
        if not phish or len(phish) < 1:
            phish = j
        if 'misp' in j and j['misp']:
            misp = j.pop('misp')

        html = ""
#	html+="<div id='detection'>"
#		html+="<div id='title'><h3> Phishing Email Submission </h3></div>"
#		html+="<table>"
#		if "m" in j:
#			html=dicttable(j["m"],html,cell='detection')
#		else:
#			html=dicttable(j,html,cell='detection')
#
#		html+="</table></div>"

        if misp:
            html += "<div id='misp'>"
            html += "<div id='title'><h3> MISP matches</h3></div>"
            html += "<table>"
            html += "<tr><b><td id='misp'>Indicator of attack</td><td id='misp'>Date</td><td id='misp'>MISP Event</td><td id='misp'>Tags</td><td id='misp'>Attribute count</td></b></tr>\n"
#			lh.debug(json.dumps(misp,sort_keys=True,indent=4))
            for m in misp:
                mr = misprow(m, conf)
                html += mr
                if mr:
                    mispfound = True
            html += "</table></div>"

        html += "<div id='userinfo'>"
        html += "<div id='title'><h3> AD Information for User</h3></div>"
        html += "<table>"
        blacklist = [
            "instanceType",
            "codePage",
            "msExchRecipientTypeDetails",
            "countryCode",
            "msExchUserAccountControl",
            "lastLogoff"]
        info = {}
        for i in adinfo:
            if not i in blacklist:
                info[i] = adinfo[i]

        html = dicttable(info, html, cell='userinfo')
        html += "</table></div>"

#	html+="<div id='computerinfo'>"
#	html+="<div id='title'><h3> AD Information for Computer</h3></div>"
#	html+="<table>"
#	html=dicttable(computerinfo,html,cell='computerinfo')
#	html+="</table></div>"

#	html+="<div id='falconhost'>"
#	html+="<div id='title'><h3> FalconHost Data</h3></div>"

#	html+="<table>"
#	for d in falconhost:
#		html=dicttable(d,html,cell='falconhost')
#	html+="</table></div>"

        html += "<div id='falcon'>"
        html += "<div id='title'><h3> Recent Crowdstrike Falcon Detections  </h3></div>"

        for d in falcon[:3]:
            html += "<table>"
            e = d
            if "event" in d:
                e = d["event"]
            detect = {}
            if 'adenrichment' in d:
                d.pop('adenrichment')
            blacklist = [
                "ScanResults",
                "QuarantineFiles",
                "adenrichment",
                "PatternDispositionDescription",
                "PatternDispositionFlags"]
            for k in e:
                if not k in blacklist:
                    detect[k] = e[k]
            html = dicttable(detect, html, 'falcon')
            html += "</table><br><br>"

        html += "<div id='fireeye'>"
        html += "<div id='title'><h3> Recent FireEye Detections</h3></div>"
        for d in feye[:3]:
            html += "<table>"
            if 'adenrichment' in d:
                d.pop('adenrichment')

            html = dicttable(d, html, cell='fireeye')
            html += "</table><br><br>"

        html += "</div>"
        html += "</body></html>"
#	feye=falcon=phish=adinfo=falconhost={}
        if feye:
            j["FalconDetections"] = falcon
        if phish:
            j["FireEyeDetections"] = feye
        if adinfo:
            j["adenrichment"] = adinfo

        mail.body += "<html><head>" + style + "</head><body>" + html
        lh.debug("Done formatting email analysis")
        cats = ["Processed"]
        if mispfound:
            cats.append("MISP Match")
        if not isinstance(mail.categories, list):
            mail.categories = cats  # ["Processed"]
        else:
            mail.categories += cats
        mail.save()

        return html
    except Exception as e:
        lh.exception(str(e))
        traceback.print_exc()
        print j


def phishingformatmd(j, mail):
    if not isinstance(mail.categories, list):
        mail.categories = ["Processed"]
    else:
        mail.categories.append("Processed")
    mail.save()
    return json.dumps(j, indent=4, sort_keys=True)
