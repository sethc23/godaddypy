import logging

import requests

__all__ = ['Client']


class Client(object):
    """The GoDaddyPy Client.

    This client is used to connect to the GoDaddy API and to perform requests with said API.
    
    More Info:  https://developer.godaddy.com/ 

    """
    logging.basicConfig(filemode='a',
                        level=logging.INFO)

    def __init__(self, account):
        """Create a new `godaddypy.Client` object

        :type account: godaddypy.Account
        :param account: The godaddypy.Account object to create auth headers with.
        """

        self.API_TEMPLATE = 'https://api.godaddy.com/v1'

        """
        {type}:  [ 'A', 'AAAA', 'CNAME', 'MX', 'NS', 'SOA', 'SRV', 'TXT' ]
        {name}:  ( the subdomain name )
        """

        self.GET_DOMAINS = '/domains'
        self.GET_DOMAIN = '/domains/{domain}'
        self.GET_RECORDS_TYPE_NAME = '/domains/{domain}/records/{type}/'
        self.PUT_RECORDS_TYPE_NAME = '/domains/{domain}/records/{type}/{name}'
        self.PATCH_RECORDS = '/domains/{domain}/records'
        self.PUT_RECORDS = '/domains/{domain}/records'

        self.account = account

    @staticmethod
    def _log_response_from_method(req_type, resp):
        logging.info('[{req_type}] response: {resp}'.format(resp=resp, req_type=req_type.upper()))
        logging.debug('Response data: {}'.format(resp.content))

    @staticmethod
    def _remove_key_from_dict(dictionary, key_to_remove):
        return {key: value for key, value in dictionary.items() if key != key_to_remove}

    @staticmethod
    def _validate_response_success(response):
        if response.status_code != 200:
            raise BadResponse(response.json())

    def _get(self, url, method_name, **kwargs):
        resp = requests.get(url, **kwargs)
        self._log_response_from_method('get', resp)
        self._validate_response_success(resp)
        return resp

    def _get_headers(self):
        return self.account.get_auth_headers()

    def _put(self, url, method_name, **kwargs):
        resp = requests.put(url, **kwargs)
        self._log_response_from_method('put', resp)
        self._validate_response_success(resp)
        return resp

    def _scope_control_account(self, account):
        if account is None:
            return self.account
        else:
            return account

    def get_domains(self):
        url = self.API_TEMPLATE + self.GET_DOMAINS
        data = self._get(url, method_name=self.get_domains.__name__, headers=self._get_headers()).json()

        domains = list()
        for item in data:
            domain = item['domain']
            if item['status'] == 'ACTIVE':
                domains.append(domain)
                logging.info('Discovered domains: {}'.format(domain))

        return domains

    def get_api_url(self):
        return self.API_TEMPLATE

    def get_domain_info(self, domain):
        """Get the GoDaddy supplied information about a specific domain.

        :param domain: The domain to obtain info about.

        :type domain: str
        """
        url = self.API_TEMPLATE + self.GET_DOMAIN.format(domain=domain)
        return self._get(url, method_name=self.get_domain_info.__name__, headers=self._get_headers()).json()

    def chk_rec_type(self, record_type):
        possible_types = [ 'A', 'AAAA', 'CNAME', 'MX', 'NS', 'SOA', 'SRV', 'TXT' ]
        assert possible_types.count(record_type.upper()),'\n\nUnknown record type: "%s"; Expected one of %s\n\n' % (record_type.upper(),str(possible_types))

    def get_records(self, domain, record_type=None):

        self.chk_rec_type(record_type)
        url = self.API_TEMPLATE + self.GET_RECORDS_TYPE_NAME.format(domain=domain, type=record_type)
        data = self._get(url, method_name='get_%s_records' % record_type.lower(), headers=self._get_headers()).json()

        logging.info('Retrieved {} records from {}.'.format(len(data), domain))

        return data

    def put_records(self, domain, records):
        for _rec in records:
            self.chk_rec_type(_rec['type'])
            url = self.API_TEMPLATE + self.PUT_RECORDS_TYPE_NAME.format(domain=domain, type=_rec['type'], name=_rec['name'])
            self._put(url, json=_rec, method_name='get_%s_records' % _rec['type'].lower(), headers=self._get_headers())
            logging.info('Updated {} records @ {}'.format(len(records), domain))

    # def get_a_records(self, domain):
    #     url = self.API_TEMPLATE + self.GET_RECORDS_TYPE_NAME.format(domain=domain, type='A')
    #     data = self._get(url, method_name=self.get_a_records.__name__, headers=self._get_headers()).json()

    #     logging.info('Retrieved {} records from {}.'.format(len(data), domain))

    #     return data

    # def put_a_records(self, domain, records):
    #     for _rec in records:
    #         url = self.API_TEMPLATE + self.PUT_RECORDS_TYPE_NAME.format(domain=domain, type='A', name=_rec['name'])
    #         self._put(url, json=_rec, method_name=self.get_a_records.__name__, headers=self._get_headers())
    #         logging.info('Updated {} records @ {}'.format(len(records), domain))

    def update_ip(self, ip, domains=None, subdomains=None):
        """Update the IP address in all A records to the value of ip.  Returns True if no exceptions occurred during
        the update.  If no domains are provided, all domains returned from self.get_domains() will be updated.

        :param ip: The new IP address (eg. '123.1.2.255')
        :param domains: A list of the domains you want to update (eg. ['123.com','abc.net'])
        :param subdomains: A list of the subdomains you want to update (eg. ['www','dev'])

        :type ip: str
        :type domains: str, list of str
        :type subdomains: str, list of str
        """

        if domains is None:
            domains = self.get_domains()
        elif type(domains) == str:
            domains = [ domains ]
        elif type(domains) == list:
            pass
        else:
            raise SystemError("Domains must be type 'list' or type 'str'")

        for domain in domains:
            import ipdb as I; I.set_trace()
            records = self.get_records(domain,'A')
            new_records = []
            for record in records:
                r_name = str(record['name'])
                r_ip = str(record['data'])

                if not r_ip == ip:

                    if (
                        ( subdomains is None )
                        or ( type(subdomains) == list 
                                and subdomains.count(r_name) )
                        or ( type(subdomains) == str 
                            and subdomains == r_name )
                        ):

                        logging.info('Preparing to update IP for "{}" subdomain of {}'.format(r_name, domain))

                        data = {'data': unicode(ip)}
                        record.update(data)

                        new_records.append(record)

            self.put_records(domain, new_records)

        # If we didn't get any exceptions, return True to let the user know
        return True


class BadResponse(Exception):
    def __init__(self, message, *args, **kwargs):
        self._message = message
        super(*args, **kwargs)

    def __str__(self, *args, **kwargs):
        return 'Response Data: {}'.format(self._message)
