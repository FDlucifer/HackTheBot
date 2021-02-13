import requests
import config as cfg
import json

class HTBApi():
    api_url =  cfg.HTB['api_url']
    endpoints = {
        'login': api_url + '/login',
        # challenges
        'challenge_active_list': api_url + '/challenge/list',
        'challenge_retired_list': api_url + '/challenge/list/retired',
        'challenge_categories_list': api_url + '/challenge/categories/list',
        'challenge_info': api_url + '/challenge/info',
        # machines
        'machine_active_list': api_url + '/machine/list',
        'machine_retired_list': api_url + '/machine/list/retired',
        'machine_activity': api_url + '/machine/activity',
        'machine_profile': api_url + '/machine/profile',
        'machine_writeup': api_url + '/machine/writeup',
        'machine_walkthroughs': api_url + '/machine/walkthroughs',
        # profile
        'profile': api_url + '/profile',
        'profile_activity': api_url + '/profile/activity',
        'profile_badges': api_url + '/profile/badges',
        'profile_progress_machines': api_url + '/profile/progress/machines/os',
        'profile_progress_challenges': api_url + '/profile/progress/challenges',
        'profile_progress_prolab': api_url + '/profile/progress/prolab',
        'profile_progress_fortress': api_url + '/profile/progress/fortress',
        'profile_progress_endgame': api_url + '/profile/progress/endgame',
    }
    default_headers = {
        'Accept': 'application/json, */*',
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:86.0) Gecko/20100101 Firefox/86.0'
    }
    
    def __init__(self):
        # proxies
        self.proxies = {
            'http': 'http://127.0.0.1:8080',
            'https': 'http://127.0.0.1:8080',
        }

        # requests session
        self.session = requests.Session()
        self.session.headers.update(self.default_headers)

        # proxy via requests
        self.proxy_session = requests.Session()
        self.proxy_session.headers.update(self.default_headers)
        self.proxy_session.proxies.update(self.proxies)
        self.proxy_session.verify = False

        # Flag for PDF download
        self.pdf = False

        self.tokens = {}

        # Login and get Access Key
        if self.login() is False:
            print('Connection error')
            exit()
        

    def login(self):
        print("Getting token...")
        data = {
            'email': cfg.HTB['email'],
            'password': cfg.HTB['password']
            }
        response = self.send_request('login', 'post', data, False)
        if response is not False:
            self.tokens = response['message']
        
        return response

    #def renew_tokens(self):


    def machines_list(self, state='active'):
        if state=='active':
            return self.send_request('machine_active_list', 'get')

        if state=='retired':
            return self.send_request('machine_retired_list', 'get')

    def machine_profile(self, machine: int):
        return self.send_request('machine_profile', 'get', machine)

    def machine_activity(self, machine: int):
        return self.send_request('machine_activity', 'get', machine)

    def machine_writeup(self, machine: int):
        self.pdf = True
        return self.send_request('machine_writeup', 'get', machine)

    def machine_walkthroughs(self, machine: int):
        return self.send_request('machine_walkthroughs', 'get', machine)

    def challenges_list(self, state='active'):
        if state=='active':
            return self.send_request('challenge_active_list', 'get')

        if state=='retired':
            return self.send_request('challenge_retired_list', 'get')

    def challenge_info(self, challenge: int):
        return self.send_request('challenge_info', 'get', challenge)

    def challenge_activity(self, challenge: int):
        return self.send_request('challenge_activity', 'get', challenge)

    def challenge_categories(self):
        return self.send_request('challenge_categories_list', 'get')

    def profile(self, user: int):
        return self.send_request('profile', 'get', user)

    def profile_activity(self, user: int):
        return self.send_request('profile_activity', 'get', user)

    def profile_progress_machines(self, user: int):
        return self.send_request('profile_progress_machines', 'get', user)

    def profile_progress_challenges(self, user: int):
        return self.send_request('profile_progress_challenges', 'get', user)

    def get_headers(self, token=True):
        headers = self.default_headers
        if token:
            headers['Authorization'] = 'Bearer ' + self.tokens['access_token']

        return headers

    def send_request(self, endpoint, method, data=None, token=True):
        # set headers
        headers = self.get_headers(token)
        # send request based on given method
        if method == 'get':
            url = self.endpoints[endpoint]
            # append data to url
            if data is not None:
                url = url + '/' + str(data)
            r = self.session.get(url, headers=headers)
        elif method == 'post':
            r = self.session.post(self.endpoints[endpoint], data=data, headers=headers)
        else:
            return False

        # Process response
        if r.status_code == 200:
            # send correct response
            if self.pdf:
                self.pdf = False
                return r
            return json.loads(r.text)
        elif r.status_code == 401:
            # regenerate expired token & resend request
            self.login()
            self.send_request(endpoint, method, data, token)
        else:
            # display error returned in terminal
            print("HTTP %i - %s, Message %s" % (r.status_code, r.reason, r.text))
            return False
        
        return False