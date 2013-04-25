# -*- coding: utf-8 -*-
# 是否使用ini作为配置文件，0不使用
ini_config = 1366077655
# 监听ip
listen_ip = '127.0.0.1'
# 监听端口
listen_port = 8086
# 是否使用通配符证书
cert_wildcard = 1
# 更新PAC时也许还没联网，等待tasks_delay秒后才开始更新
tasks_delay = 0
# WEB界面是否对本机也要求认证
web_authlocal = 0
# 登录WEB界面的用户名
web_username = 'admin'
# 登录WEB界面的密码
web_password = 'admin'
# 全局代理
global_proxy = None
# URLFetch参数
fetch_keepalive = 1
check_update = 0

def config():
    Forward, set_dns, set_resolve, set_hosts, check_auth, redirect_https = import_from('util')
    FORWARD = Forward()
    set_dns('8.8.8.8')
    set_resolve('talk.google.com talkx.l.google.com .youtube.com')
    google_sites = ('.appspot.com', '.google.com', '.google.com.hk', '.googlecode.com', '.googleusercontent.com', '.googlegroups.com', '.google-analytics.com', '.gstatic.com', '.googleapis.com', '.blogger.com', '.ggpht.com')
    google_hosts = 'www.google.com www.google.com.hk mail.google.com www.google-analytics.com 74.125.128.59 74.125.128.54 74.125.128.102 74.125.128.101 74.125.128.83 74.125.128.17 74.125.128.51 74.125.128.35 74.125.128.45 74.125.128.106 74.125.128.50 74.125.128.65 74.125.128.104 74.125.128.138 74.125.128.96'
    set_hosts(google_sites, google_hosts)
    set_hosts('www.youtube.com upload.youtube.com', google_hosts)

    from plugins import paas; paas = install('paas', paas)
    GAE = paas.GAE(appids=['x2anywhere'], listen='8087', path='/fetch.py', scheme='https', hosts=google_hosts, maxsize=500000, waitsize=100000, max_threads=3, fetch_mode=1)

    PacFile, RuleList, HostList = import_from('pac')
    forcehttps_sites = RuleList('http://*.appspot.com/ \n http://*.google.com/ \n http://*.google.com.hk/ \n http://*.googlecode.com/ \n http://*.googleusercontent.com/ \n http://*.blogger.com/ \n @@http://books.google.com/ \n @@http://translate.google.com/ \n @@http://scholar.google.com/ \n @@http://feedproxy.google.com/ \n @@http://fusion.google.com/ \n @@http://picasa.google.com/ \n @@http://*pack.google.com/ \n @@http://*android.clients.google.com/ \n @@http://www.google.com*/imgres? \n @@http://www.google.com*/translate_t? \n @@http://www.google.com/analytics/ \n @@http://wiki.*.googlecode.com/ \n @@http:/// \n @@http://website.*.googlecode.com/ \n @@http://www.google.com*/custom? \n @@http://www.google.com/dl/')
    autorange_rules = RuleList('||c.youtube.com \n ||c.docs.google.com \n ||googlevideo.com \n http*://av.vimeo.com/ \n http*://smile-*.nicovideo.jp/ \n http*://video.*.fbcdn.net/ \n http*://s*.last.fm/ \n http*://x*.last.fm/ \n /^https?:\\/\\/[^\\/]+\\/[^?]+\\.(?:f4v|flv|hlv|m4v|mp4|mp3|ogg|avi|exe)(?:$|\\?)/ \n http*://*.googleusercontent.com/videoplayback?')
    _GAE = GAE; GAE = lambda req: _GAE(req, autorange_rules.match(req.url, req.proxy_host[0]))
    import re; useragent_match = re.compile('(?i)mobile').search
    useragent_rules = RuleList('||twitter.com')
    withgae_sites = RuleList('||c.docs.google.com \n ||translate.google.com \n ||play.google.com \n http*://books.google.com/books?id= \n http*://*.googleusercontent.com/videoplayback?')
    notruehttps_sites = HostList('.docs.google.com translate.google.com play.google.com books.google.com')
    truehttps_sites = HostList('.appspot.com .google.com .google.com.hk .googlecode.com .googleusercontent.com .googlegroups.com .google-analytics.com .gstatic.com .googleapis.com .blogger.com .ggpht.com')
    crlf_rules = RuleList('/^https?:\\/\\/[^\\/]+\\.c\\.youtube\\.com\\/liveplay\\?/ \n /^https?:\\/\\/upload\\.youtube\\.com\\// \n /^https?:\\/\\/www\\.youtube\\.com\\/upload\\//')
    hosts_rules = RuleList(' \n ||appspot.com \n ||google.com \n ||google.com.hk \n ||googlecode.com \n ||googleusercontent.com \n ||googlegroups.com \n ||google-analytics.com \n ||gstatic.com \n ||googleapis.com \n ||blogger.com \n ||ggpht.com')
    FORWARD.http_failed_handler = GAE

    rulelist = (
        (RuleList(['https://autoproxy-gfwlist.googlecode.com/svn/trunk/gfwlist.txt', 'userlist.ini']), GAE),
    )
    httpslist = (
        (rulelist[0][0], None),
    )
    unparse_netloc = import_from(install('utils', lambda:globals().update(vars(utils))))

    def find_gae_handler(req):
        proxy_type = req.proxy_type
        host, port = req.proxy_host
        if proxy_type.endswith('http'):
            url = req.url
            if useragent_match(req.headers.get('User-Agent','')) and useragent_rules.match(url, host):
                req.headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.4 (KHTML, like Gecko) Chrome/22.0.1229.94 Safari/537.4'
            if withgae_sites.match(url, host):
                return GAE
            needhttps = req.scheme == 'http' and forcehttps_sites.match(url, host) and req.content_length == 0
            if needhttps and getattr(req, '_r', '') != url:
                req._r = url
                return redirect_https
            if crlf_rules.match(url, host):
                req.crlf = 1
                return FORWARD
            if not needhttps and hosts_rules.match(url, host):
                return FORWARD
            return GAE
        if notruehttps_sites.match(host): return
        if truehttps_sites.match(host): return FORWARD
    paas.data['GAE_server'].find_handler = find_gae_handler

    def find_proxy_handler(req):
        proxy_type = req.proxy_type
        host, port = req.proxy_host
        if proxy_type.endswith('http'):
            url = req.url
            if useragent_match(req.headers.get('User-Agent','')) and useragent_rules.match(url, host):
                req.headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.4 (KHTML, like Gecko) Chrome/22.0.1229.94 Safari/537.4'
            if withgae_sites.match(url, host):
                return GAE
            needhttps = req.scheme == 'http' and forcehttps_sites.match(url, host) and req.content_length == 0
            if needhttps and getattr(req, '_r', '') != url:
                req._r = url
                return redirect_https
            if crlf_rules.match(url, host):
                req.crlf = 1
                return FORWARD
            if not needhttps and hosts_rules.match(url, host):
                return FORWARD
            for rule,target in rulelist:
                if rule.match(url, host):
                    return target
            return FORWARD
        if notruehttps_sites.match(host): return
        if truehttps_sites.match(host): return FORWARD
        elif proxy_type.endswith('https'):
            url = 'https://%s/' % unparse_netloc((host, port), 443)
            for rule,target in httpslist:
                if rule.match(url, host):
                    return target
            return FORWARD
    return find_proxy_handler
