# Sweetie data

This repo contains data of various honeypots mostly gathered with awsome [t-pot!](https://github.com/dtag-dev-sec/tpotce) . What to know what malicious actors are up to? Do you believe data is the only source of truth?
There you have it. Put on your sherlock hat and find the crime. This repo contains three months of data from 12/19 to 2/20.

## Who can uses these data

- Security researchers
- Malware analysts
- Threat intelligence companies
- Universities
- Data scientists
- Anyone else interested

## Motivation

This research was a side project mainly motivated by understanding the current state of attacks in the wild.But as an individual, I have minimal resources and time so, I can't afford to scale and maintain, so I decide to take the servers down and share the data with the community. &hearts;

# How to use it

## Folder structure

Here is the list of honeypots and analyzers used during this experiment.

- adbhoney
- cowrie
- dionaea
- elasticpot
- heralding
- medpot
- p0f
- suricata
- tanner

Each honeypot has a log folder. Most of the logs are JSON or SQLite. Some honeypots contain other data, such as sample files.

## Payloads

As mentioned, some honeypots also collect files, for example, adbhoney and cowrie. You can find file archives in the root directory of each honeypot.

file samples:

```bash
380c4553681d76dca812fd679068ff42645363cf3aef11afe036252051725c7a.raw: ELF 32-bit MSB executable, Motorola m68k, 68020, version 1 (SYSV), statically linked, stripped
3c0ac166b8511744430f4869b744beeef873c9a3c857e8d6607262a8d156f796.raw: ELF 64-bit MSB executable, MIPS, MIPS64 version 1 (SYSV), statically linked, stripped
590dbe0f8c6977d808cdc66d6e46cb6579c0d42d520a74c8a27210d3b97d9930.raw: ELF 32-bit MSB executable, SPARC, version 1 (SYSV), statically linked, stripped
608ee011537005f368c9731f4c4dee6a247b620cde52908ed0678df28c617971.raw: ELF 32-bit LSB executable, ARM, EABI5 version 1 (SYSV), statically linked, BuildID[sha1]=ba88e16fed564b3e4d7aba0787c6fbab52471e50, stripped
615b1640e5ce651bfab71ee6be1244183ae244576a9eca3073dfe444eba072ad.raw: ELF 32-bit LSB executable, ARM, version 1 (ARM), statically linked, stripped
63946c28efa919809c03be75a3937c4be80589a9df79cd1be72037d493b70857.raw: ELF 32-bit LSB executable, ARM, EABI5 version 1 (SYSV), statically linked, BuildID[sha1]=0c9b76185c23d668c7b4f1bdba94dfb94a9bed7a, stripped
755286a4739343aa7f64227bcad34384df8d1602ac175b94a44068d51f237eb7.raw: ELF 32-bit LSB executable, MIPS, MIPS-I version 1 (SYSV), statically linked, stripped
76ae6d577ba96b1c3a1de8b21c32a9faf6040f7e78d98269e0469d896c29dc64.raw: ELF 32-bit LSB executable, ARM, EABI5 version 1 (SYSV), statically linked, BuildID[sha1]=0af1f8be964f83d69ec4163415260349fa6cede8, stripped
7a48c93c5cb63a09505a009260d1cca8203285e0c1c6ff5b0df9cbb470820865.raw: Java archive data (JAR)
7a656791b445fff02ac6e9dd1081cc265db935476a9ee71139cb6aef52102e2b.raw: ELF 32-bit LSB executable, ARM, EABI5 version 1 (SYSV), statically linked, BuildID[sha1]=53abe9912786eea2bd09f4af4d634454777556e5, stripped
9d8bf69ebedb94061469734f1486c0da01c1e566bf7be83ce3779aa1a0b54371.raw: ELF 32-bit LS

```

You can use [VirusTotal](https://developers.virustotal.com/reference) API for bulkscan.

# Visualation

T-pot uses Elastic Stack and [kiabana](https://www.elastic.co/kibana) dashboard .

```
Kibana lets you visualize your Elasticsearch data and navigate the Elastic Stack so you can do anything from tracking query load to understanding the way requests flow through your apps.
```

It will do a fantastic job of making sense of these data, but at the same time, these data are too detail-oriented, so for the best results, you can have to role your-own analyzer.

# Extra miles

For example, here is what I wrote to extract possible web application exploits from Suricata logs
it uses pandas to read large JSON files then filter the data frame with an entry contain HTTP next. It will check if there is a file in url.

```python

# (C) 2020 0xSha <me@0xsha.io>
#
# $Id: suricata_http_path_filter.py Sun Feb 23 20:51:13 +07 2020 0xSha $
#

import pandas as pd
import json

def list_to_dict(lst):
	it = iter(lst)
	dic_result = dict(zip(it, it))
	return dic_result


results = []
df = pd.read_json('/data/suricata/log/eve.json',lines=True)
filtered_df = df[df['http'].notnull()]

f =  pd.DataFrame(filtered_df['http'])
for i in f.iterrows():
	if "url" in i[1].to_dict()['http']:
		if i[1].to_dict()['http']['url'] != "/":
			results.append(i[1].to_dict()['http'])

sorted_results = [sorted(d.items()) for d in results]

unique_results = list(map(json.loads,set(map(json.dumps, sorted_results))))

with open("/suricata_http_paths.json" , "w") as suricata_out_http:
	for item in unique_results:
		concat_list = [j for i in item for j in i]
		suricata_out_http.writelines( str(  json.dumps(list_to_dict(concat_list) )))

```

The output is a cleaned JSON file. Here is an example of an exciting line.

```json
{"hostname": "http_content_type": "text/html", "http_method": "GET", "http_port": 80, "http_user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.108 Safari/537.36", "length": 3348, "protocol": "HTTP/1.1", "status": 404, "url": "/index.php?s=/Index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=md5&vars[1][]=HelloThinkPHP"}

```

As we see, we successfully extracted an exploit for [thinkphp](https://www.exploit-db.com/exploits/46150).

# Findings

There are too much data and endless possibility of extraction and analysis, but here are a few things that come into my mind when I want to draw a conclusion.

- The number of malicious packets transferred a day is unbeliveble.
- Fortunately, a big chunk of malicious actors are script kiddies, but somehow they still score in 2020
- Very first computer attacks like brute forces are still a thing in 2020 when it comes to protocols like VNC and SQL SERVER.
- Mixing security, machine learning, and data science can bring **"real"** next-generation defense results.

# How To Make more things like this happen?

- Share it with whomever you belive can use it
- Do the extra work and share your findings with community &hearts;
- [![ko-fi](https://www.ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/W7W112I38)

# Any ideas ?

- me [at] 0xsha.io
