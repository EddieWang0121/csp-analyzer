#!/usr/bin/python3

import sys
import requests
import urllib.parse
import json
import tldextract


# Sources:
# https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy
# https://content-security-policy.com/

t_help = {
    "child-src": "Defines the valid sources for web workers and nested browsing contexts loaded using elements such as <frame> and <iframe>.",
    "connect-src": "Restricts the URLs which can be loaded using script interfaces",
    "default-src": "Serves as a fallback for the other fetch directives.",
    "font-src": "Specifies valid sources for fonts loaded using @font-face.",
    "frame-src": "Specifies valid sources for nested browsing contexts loading using elements such as <frame> and <iframe>.",
    "img-src": "Specifies valid sources of images and favicons.",
    "manifest-src": "Specifies valid sources of application manifest files.",
    "media-src": "Specifies valid sources for loading media using the <audio> , <video> and <track> elements.",
    "object-src": "Specifies valid sources for the <object>, <embed>, and <applet> elements.",
    "prefetch-src": "Specifies valid sources to be prefetched or prerendered.",
    "script-src": "Specifies valid sources for JavaScript.",
    "style-src": "Specifies valid sources for stylesheets.",
    "webrtc-src": "Specifies valid sources for WebRTC connections.",
    "worker-src": "Specifies valid sources for Worker, SharedWorker, or ServiceWorker scripts.",

    "base-uri": "Restricts the URLs which can be used in a document's <base> element.",
    "plugin-types": "Restricts the set of plugins that can be embedded into a document by limiting the types of resources which can be loaded.",
    "sandbox": "Enables a sandbox for the requested resource similar to the <iframe> sandbox attribute.",
    "disown-opener": "Ensures a resource will disown its opener when navigated to.",

    "form-action": "Restricts the URLs which can be used as the target of a form submissions from a given context.",
    "frame-ancestors": "Specifies valid parents that may embed a page using <frame>, <iframe>, <object>, <embed>, or <applet>.",
    "navigate-to": "Restricts the URLs to which a document can navigate by any means (a, form, window.location, window.open, etc.)",

    "report-uri": "Instructs the user agent to report attempts to violate the Content Security Policy. These violation reports consist of JSON documents sent via an HTTP POST request to the specified URI.",
    "report-to": "Fires a SecurityPolicyViolationEvent.",

    "block-all-mixed-content": "Prevents loading any assets using HTTP when the page is loaded using HTTPS.",
    "referrer": "Used to specify information in the referer (sic) header for links away from a page. Use the Referrer-Policy header instead.",
    "require-sri-for": "Requires the use of SRI for scripts or styles on the page.",
    "upgrade-insecure-requests": "Instructs user agents to treat all of a site's insecure URLs (those served over HTTP) as though they have been replaced with secure URLs (those served over HTTPS). This directive is intended for web sites with large numbers of insecure legacy URLs that need to be rewritten.",

    "*": {"t":"Wildcard, allows any URL except data: blob: filesystem: schemes.","warning_level":"5"},
    "'none'": {"t":"Prevents loading resources from any source.","warning_level":"2"},
    "'self'": {"t":"Allows loading resources from the same origin (same scheme, host and port).","warning_level":"2"},
    "data:": {"t":"Allows loading resources via the data scheme (eg Base64 encoded images).","warning_level":"3"},
    "blob:": {"t":"Allows loading resources via the blob scheme (eg Base64 encoded images).","warning_level":"3"},
    "domain.example.com": {"t":"Allows loading resources from the specified domain name.","warning_level":"2"},
    "*.example.com": {"t":"Allows loading resources from any subdomain under example.com.","warning_level":"2"},
    "https://cdn.com": {"t":"Allows loading resources only over HTTPS matching the given domain.","warning_level":"2"},
    "https:": {"t":"Allows loading resources only over HTTPS on any domain.","warning_level":"2"},
    "'unsafe-inline'": {"t":"Allows use of inline source elements such as style attribute, onclick, or script tag bodies (depends on the context of the source it is applied to) and javascript: URIs.","warning_level":"5"},
    "'unsafe-eval'": {"t":"Allows unsafe dynamic code evaluation such as JavaScript eval()","warning_level":"5"},
    "'nonce-'": {"t":"Allows script or style tag to execute if the nonce attribute value matches the header value. Note that 'unsafe-inline' is ignored if either a hash or nonce value is present in the source list.","warning_level":"2"},
    "'sha256-'": {"t":"Allow a specific script or style to execute if it matches the hash. Doesn't work for javascript: URIs. Note that 'unsafe-inline' is ignored if either a hash or nonce value is present in the source list.","warning_level":"2"},
}

t_warning_level = {
    0: 'info',
    1: 'info',
    2: 'low',
    3: 'low',
    4: 'medium',
    5: 'high',
}


def usage( err='' ):
    print( "Usage: %s <url> [<cookies>]" % sys.argv[0] )
    if err:
        print( "Error: %s!" % err )
    sys.exit()


if len(sys.argv) < 2:
    usage( 'url not found' )
if len(sys.argv) > 3:
    usage()

url = sys.argv[1]
if len(sys.argv) > 2:
    t_cookies = {}
    for c in sys.argv[2].split(';'):
        c = c.strip()
        if len(c):
            i = c.index('=')
            k = c[0:i]
            v = c[i+1:]
            t_cookies[k] = v
else:
    t_cookies = {}

if not url.startswith('http'):
    url = 'https://' + url

# print("Calling %s..." % url )
r = requests.get(url, cookies=t_cookies, allow_redirects=False, headers={'User-Agent':'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:105.0) Gecko/20100101 Firefox/105.0'})


if 'Content-Security-Policy' not in r.headers:
    usage( 'Content-Security-Policy not found' )

t_csp = r.headers['Content-Security-Policy'].split( ';' )
# print("")

t_parse_orig = urllib.parse.urlparse( url )
t_tld_orig = tldextract.extract( t_parse_orig.netloc )


def getWarningLevel( t_tld_orig, item ):
    w_level = 0

    if item in t_help:
        return 0

    if not item.startswith('http'):
        item = 'https://'+item

    tmp_parse = urllib.parse.urlparse( item )
    tmp_tld = tldextract.extract( tmp_parse.netloc )

    if tmp_tld.subdomain == t_tld_orig.subdomain and tmp_tld.domain == t_tld_orig.domain and tmp_tld.suffix == t_tld_orig.suffix:
        # same subdomain and domain and tld
        w_level = 1
    elif tmp_tld.domain == t_tld_orig.domain and tmp_tld.suffix == t_tld_orig.suffix:
        # same domain and tld
        w_level = 2
    elif tmp_tld.domain == t_tld_orig.domain:
        # same domain name
        w_level = 3
    else:
        # nothing in common
        w_level = 4

    if '*' in tmp_parse.netloc:
        # it's a wildcard!
        w_level+=1

    return w_level

json_list={"result":[]}

for csp in t_csp:
    json_obj={"policy":"", 
              "description":"", 
              "warning_level":"", 
              "orig_item":"", 
              "additional":""}
    csp = csp.strip()
    if not len(csp):
        continue
    tmp = csp.split( ' ' )
    policy = tmp.pop( 0 )
    if policy:
        if not len(policy):
            continue
        # sys.stdout.write("%s" % (policy) )
        json_obj["policy"]=policy

        if policy in t_help:
            # sys.stdout.write("[%s]" % (t_help[policy]))
            json_obj["description"]=t_help[policy]

        # sys.stdout.write( "\n" )
        for item in tmp:
            if not len(item):
                continue
            orig_item = item
            if item.startswith("'nonce-"):
                item = "'nonce-'"
            elif item.startswith("'sha256-"):
                    item = "'sha256-'"
            if item in t_help:
                warning_level = t_help[item]['warning_level']
            else:
                w_level = getWarningLevel( t_tld_orig, item )
                warning_level = t_warning_level[w_level]

            # sys.stdout.write(" warning_level - %s:" % (warning_level) )
            json_obj["warning_level"] = warning_level

            # sys.stdout.write( "%s" % orig_item )
            json_obj["orig_item"] = orig_item

            if item in t_help:
                # sys.stdout.write( "[%s]" % (t_help[item]['t']) )
                json_obj["additional"] = t_help[item]['t']
            # sys.stdout.write( "\n" )
    # sys.stdout.write( "\n" )
    json_list["result"].append(json_obj)

print(json.dumps(json_list))
