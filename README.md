# IP_lookup
A python script to perform reverse lookup and curl operation to get full redirected URL.

Dependencies : pycurl, dnspython

NOTE: Program will remove any file(s) if exists:
<Input file name>_redirected_URL.txt
<Input file name>_reverse_hostname.txt

For example:
Input File name : test.txt
output file / truncated file : test_redirected_URL.txt , test_reverse_hostname.txt

Future plans:

1. ping
2. multithreaded
3. Creates XLSX file instead of TXT file

Bugs ATM :

1. for some IP, there might be some weird output from curl

i.e web/http://xxx.xxx.xx.xx/web/index.php?r=site/login

Idea to fix : make sure URL starts with 'http'

2. Unable to follow redirection from javascript
