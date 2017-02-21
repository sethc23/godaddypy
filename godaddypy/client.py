import logging

import requests

import netaddr

__all__ = ['Client']


class Client(object):
    """The GoDaddyPy Client.

    This client is used to connect to the GoDaddy API and to perform requests with said API.

    More Info:  https://developer.godaddy.com/

    # TODO: add method for deleting records

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
        self.GET_RECORDS_TYPE = '/domains/{domain}/records/{type}'
        self.GET_RECORDS_TYPE_NAME = '/domains/{domain}/records/{type}/{name}'
        self.PATCH_RECORDS = '/domains/{domain}/records'
        self.PUT_RECORDS = '/domains/{domain}/records'
        self.PUT_RECORDS_TYPE_NAME = '/domains/{domain}/records/{type}/{name}'

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
            try:
                api_error_code = eval(response.content)['code']
                if api_error_code=="DUPLICATE_RECORD":
                    print('\n\nError: Duplicate Record:')
                    for _err in eval(response.content)['errors']:
                        print('\t%s' % _err)
                    print('\n\n')
                    return
            except:
                pass
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

    def chk_rec_type_defined(self, record):
        if not record:
            record = {}
        if record.has_key('record_type'):
            pass
        else:
            if netaddr.valid_ipv4(record['address']):
                record['record_type']='A'
            elif netaddr.valid_ipv6(record['address']):
                record['record_type']='AAAA'
            else:
                record['record_type']='CNAME'

            # TODO: extend support for TXT,SRV,NX, etc...

        return record

    def chk_rec_type_avail(self, record=None, return_all_types_only=False):
        possible_types = [ 'A', 'AAAA', 'CNAME']
        # possible_types = [ 'A', 'AAAA', 'CNAME', 'MX', 'NS', 'SOA', 'SRV', 'TXT' ]
        if return_all_types_only:
            return possible_types
        record_type = record if not type(record)==dict else record['record_type']
        assert possible_types.count(record_type.upper()),'\n\nUnknown record type: "%s"; Expected one of %s\n\n' % (record_type.upper(),str(possible_types))

    def get_records(self, domain, record_type='all', subdomains=None):
        """Get records for a domain of the record_type {'A','AAAA','CNAME','MX','NS','SOA','SRV','TXT'}.

        :param domain: The domain from which to obtain records.
        :param record_type: The type of records {'A','AAAA','CNAME','MX','NS','SOA','SRV','TXT'} from which to obtain records.

        :type domain: str
        :type record_type: str

        """
        record_type = record_type if not record_type=='all' else self.chk_rec_type_avail(return_all_types_only=True)
        record_type = record_type if type(record_type)==list else [ record_type ]
        res_data = []
        for _rec in record_type:
            self.chk_rec_type_avail(_rec)
            if not subdomains:
                url = self.API_TEMPLATE + self.GET_RECORDS_TYPE.format(domain=domain, type=_rec)
                data = self._get(url, method_name='get_%s_records' % _rec.lower(), headers=self._get_headers()).json()
                res_data.extend(data)

                logging.info('Retrieved {} records from {}.'.format(len(data), domain))

            else:
                subdomains = subdomains if type(subdomains)==list else [ subdomains ]
                for _sub in _rec['subdomains']:
                    url = self.API_TEMPLATE + self.PUT_RECORDS_TYPE_NAME_TYPE.format(domain=domain, type=_rec, name=_sub)
                    data = self._get(url, method_name='get_%s_records' % _rec.lower(), headers=self._get_headers()).json()
                    res_data.extend(data)

                    logging.info('Retrieved {} records from {}.'.format(len(data), domain))

        return res_data

    def put_records(self, domain, records):
        """
        "param records: A dictionary with relavant values to keys: address,record_type,subdomain"
        """
        if not type(records)==list:
            records = [ records ]

        for _rec in records:
            _rec = self.chk_rec_type_defined(_rec)
            self.chk_rec_type_avail(_rec)
            _rec['subdomains'] = _rec['subdomains'] if type(_rec['subdomains'])==list else [ _rec['subdomains'] ]
            for _sub in _rec['subdomains']:
                url = self.API_TEMPLATE + self.PUT_RECORDS_TYPE_NAME.format(domain=domain, type=_rec['record_type'], name=_sub)
                _gp = {'type':_rec['record_type']
                        ,'name':_sub
                        ,'data':_rec['address']
                        ,'ttl':1800
                        } if _rec['address'] else []

                self._put(url, json=_gp, method_name='get_%s_records' % _rec['record_type'].lower(), headers=self._get_headers())
                logging.info('Updated {} records @ {}'.format(len(_rec), domain))


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

    def update_record(self, address, domains=None, subdomains=None, record_type='auto-detect'):
        """Update the IP address in all A records to the value of ip.  Returns True if no exceptions occurred during
        the update.  If no domains are provided, all domains returned from self.get_domains() will be updated.

        :param record_type: The record type to update, i.e., 'A','CNAME',etc...
        :param ip: The new IP address (eg. '123.1.2.255')
        :param domains: A list of the domains you want to update (eg. ['123.com','abc.net'])
        :param subdomains: A list of the subdomains you want to update (eg. ['www','dev'])

        :type record_type: str, list of str
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
            records = self.get_records(domain,record_type)
            new_records = []
            for record in records:
                r_name = str(record['name'])
                r_addr = str(record['data'])

                if not r_addr == address:

                    if (
                        ( subdomains is None )
                        or ( type(subdomains) == list
                                and subdomains.count(r_name) )
                        or ( type(subdomains) == str
                            and subdomains == r_name )
                        ):

                        logging.info('Preparing to update address for "{}" subdomain of {}'.format(r_name, domain))

                        data = {'data': unicode(address)}
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
