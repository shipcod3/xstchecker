# xstchecker.py
# description: checks if the website is vulnerable to Cross-Site Tracing ()
# author: @shipcod3

import sys, httplib

def usage():
     print("USAGE: python xstchecker.py host.com")  
     
def main(argv):
  
    if len(argv) < 1:
        return usage()
      
    host = sys.argv[1]
    payload = "<script>alert('TRACE');</script>"

    print "[***] Checking: {0} for Cross-Site Tracing \n".format(host)

    try:  
        conn = httplib.HTTPConnection(host)
        conn.request("TRACE", "/{0}".format(payload))
        response = conn.getresponse()
        msg = response.read()
        print response.status, response.reason, msg
    
        if response.status == 200 and "<script>alert('TRACE');</script>" in msg:
            print "[!] Vulnerable to Cross-Site Tracing!" 
        else:
            print "[-] Not Vulnerable!"   
    except:
        print "[-] Error! Check if host is online..."
        
if __name__ == "__main__":
    main(sys.argv)
