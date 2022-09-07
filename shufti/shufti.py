import ssl, socket
import requests

def check_net():
    try:
        socket.create_connection(("1.1.1.1", 53))
    except OSError:
        pass
        print("Not connected to the internet")
        exit()

def get_ip(u):
    if "https://" in u:
        u = u.removeprefix("https://")        
    print("\n\nIPv4 address -> "+socket.gethostbyname(u))
    u = "https://"+u
    r = requests.get(u, stream=True)
    # l = r.raw._connection.sock.getsockname()
    # print("IPv6 address -> "+l[0])
    return r

def header_info(resp):
    if resp.ok:
        info = dict(resp.headers)
        l = list(resp.headers)

        print("\nRESPONSE HEADER\n"+"-"*25)
        for i in range(len(l)):
            print(f"{l[i]}:{info[l[i]]}")

def metadata_files_v(u):
    li = ["/robots.txt", "/security.txt", "/.well-known/security.txt", "/humans.txt"]
    for i in range(len(li)):
        r = requests.get(f"{u}{li[i]}")
        if r.ok and r.content!=b'\n':
            print("\n"+"#"*10+li[i].upper()+"#"*10+"\n")
            print(r.text)
    r = requests.get(u+"/sitemap.xml")
    if r.ok and r.content!=b'\n':
        print("\n"+"#"*10+"SITEMAP.XML FOUND"+"#"*10+"\n")

def config_testing(u, resp):
    #OPTIONS request
    r = requests.options(u)
    if r.ok:
        print(f"\n\nSUPPORTED HTTP METHODS ARE:{r.text}")
    #check for method overriding
    rh = str(resp.headers)
    lx = ["X-HTTP-Method", "X-HTTP-Method-Override", "X-Method-Override"]
    for i in range(len(lx)):
        if lx[i] in rh:
            print(f"HTTP method overriding might be possible using {lx[i]}")
    #test for HSTS
    lh = ["Strict-Transport-Security", "max-age", "includeSubDomains", "preload"]
    if lh[0] in rh:
        print("\n\nHSTS header: present")
        for i in range(1, len(lh)):
            if lh[i] not in rh:
                print(f"Recommended to use HSTS directive '{lh[i]}'")
    else:
        print("HSTS header: absent")

def dig_cert_test(u:str):
    hostname = u.removeprefix("https://")
    print(f"\nPrinting digital certificate data of {hostname}\n"+"-"*75)
    ctx = ssl.create_default_context()
    with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
        s.connect((hostname, 443))
        cert = s.getpeercert()

    l = list(cert)
    for i in range(len(l)):
        print(f"{l[i]}:{cert[l[i]]}")


def main():
    check_net()

    url = input("Enter a url:") #for example, url = "https://owasp.org"
    r = get_ip(url)
    url = "https://"+url

    header_info(r)
    metadata_files_v(url)
    config_testing(url, r)
    dig_cert_test(url)

if __name__=="__main__":
    main()
