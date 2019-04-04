import html as h
import traceback
import json
style = '''
<style>
  @font-face {
  font-family: 'Orbitron';
  font-style: normal;
  font-weight: 400;
  src: local('Orbitron Regular'), local('Orbitron-Regular'), url(galleryimages/orbitron.woff2) format('woff2');
  unicode-range: U+0000-00FF, U+0131, U+0152-0153, U+02BB-02BC, U+02C6, U+02DA, U+02DC, U+2000-206F, U+2074, U+20AC, U+2122, U+2191, U+2193, U+2212, U+2215, U+FEFF, U+FFFD;
}

  body {

    font-family: Courier;
    font-size: 18px;
		background-color: #222;
		color:#fff;
}
#main {
	    display: inline-block;
}

.label{
	text-align:left;
}
.login {
	margin-left:30%;
	margin-right:30%;
}
#header {
	font-size:54px;
	color:#1c3642;
}
#banner {
	font-size:24px;
	text-align: center;
	color:#1c3642;
}
#output {
	border: solid 1px black;
	font-family:courier !important;
}
pre {

	color:#dd1f3b;
}

table{
	margin-left:20px;
	border-width:10px;

}
td {
	border: solid 1px;
	margin-left:20px;
	padding:3px;
	color:#bbd4de;

}
#title{
	font-size:20px;
	margin-left:25px;
	text-align: center;
}
.detection,#detection{
background-color:#281819;
}
#key{
	font-weight:bold;
	font-size:16px;
}
.userinfo,.computerinfo,#userinfo,#computerinfo{
	background-color:#003249;
}
.falconhost,#falconhost{
	background-color:#260119
}
.falcon,#falcon{
	background-color:#000033;
}
.phishing,#phishing{
	background-color:#131a21;
}
a {
	color:white;
	background-color:black;
}
#ts {
	text-align:left !important;
	font-weight: bold;
	font-size:20px !important;
	margin-left:20px;
}
#result {
	border-left:solid 10px #385369;
}


#title{

}
</style>
'''


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
                html += "<td id='key' class='" + cell + "'>" + key + "</td><td id='value' class='" + \
                    cell + "'><pre>" + \
                        h.escape(
                            json.dumps(
                                j[k],
                                sort_keys=True,
                                indent=4)) + "</pre></td>"
        except BaseException:
            print j
            traceback.print_exc()
        html += "</tr>"
    return html


def fireeyeformat(j):
    feye = falcon = phish = adinfo = falconhost = {}
    if "FalconDetections" in j:
        falcon = j.pop("FalconDetections")
    if "ReportedPhishing" in j:
        phish = j.pop("ReportedPhishing")
    if "adenrichment" in j:
        adinfo = j.pop("adenrichment")
    feye = j.pop("alert")
#	falconhost=j.pop("FalconHostData")

    html = "<html><head>" + style + "</head><body>"
    html += "<div id='detection'>"
    html += "<div id='title'><h3> FireEye EX Retroactive Detection</h3></div>"
    html += "<table>"
    html = dicttable(feye, html, cell='detection')
    html += "</table></div>"

    html += "<div id='userinfo'>"
    html += "<div id='title'><h3> AD Information for User</h3></div>"
    html += "<table>"
    html = dicttable(adinfo, html, cell='userinfo')
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
    html += "<div id='title'><h3> Recent Crowdstrike Falcon Detections </h3></div>"

    for d in falcon:
        html += "<table>"

        if 'adenrichment' in d:
            d.pop('adenrichment')
        html = dicttable(d, html, 'falcon')
        html += "</table><br><br>"

    html += "<div id='phishing'>"
    html += "<div id='title'><h3> Recently reported phishing emails</h3></div>"
    for d in phish:
        html += "<table>"
        if 'adenrichment' in d:
            d.pop('adenrichment')
        m = None
        if 'm' in d:
            m = d.pop('m')

        html = dicttable(d, html, cell='phishing')
        if m:
            html = dicttable(m, html, prepend="Phish_", cell='phishing')
        html += "</table><br><br>"

    html += "</div>"
    html += "</body></html>"
#	feye=falcon=phish=adinfo=falconhost={}
    if falcon:
        j["FalconDetections"] = falcon
    if phish:
        j["ReportedPhishing"] = phish
    if adinfo:
        j["adenrichment"] = adinfo
    j["alert"] = feye
    return html


def fireeyeformatmd(j):
    return json.dumps(j, indent=4, sort_keys=True)
