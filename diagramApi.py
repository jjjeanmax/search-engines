from datetime import datetime as date_ti
from datetime import date
import datetime

import sys
import json
import os
from pathlib import Path
from collections import Counter

import matplotlib.pyplot as plt
import shodan
from censys.search import CensysHosts
import zoomeye.sdk as zoomeye

secrets_path = os.path.join(Path(__file__).resolve().parent, 'configs.json')
with open(secrets_path) as f:
    secrets_data = json.loads(f.read())


def get_secret(setting, section=None, secrets=None):
    if secrets is None:
        secrets = secrets_data

    try:
        if section:
            return secrets[section][setting]
        return secrets[setting]
    except KeyError:
        key = setting if not section else '%s["%s"]' % (section, setting)
        error_message = 'Secrets: {} key not found in configs.json.'.format(key)
        raise (error_message)


def get_data_shodan_api():
    '''
    Use Shodan Api to get data (Country and ASN) for last 3 month
    '''

    global dict_country, dict_asn, dict_country_3_month, dict_asn_3_month, query
    SHODAN_API_KEY = get_secret(section="SHODAN", setting="SHODAN_API_KEY")

    # The list of properties we want summary information on
    FACETS = [
        'asn',
        'country',
    ]

    # Input validation
    if len(sys.argv) == 1:
        print('Usage: %s <search query>' % sys.argv[0])
        sys.exit(1)

    try:
        # Setup the api
        api = shodan.Shodan(SHODAN_API_KEY)

        # Generate a query string out of the command-line arguments
        query = ' '.join(sys.argv[1:])

        # get data for last 3 month
        list_times = []
        list_asn = []
        list_country = []
        list_asn_all_time = []
        list_country_all_time = []
        # 3 month
        time_delta = datetime.timedelta(days=90)

        for qs in (api.search(query)['matches']):
            if 'asn' in qs.keys():
                list_asn_all_time.append(qs['asn'])
            if 'location' in qs.keys():
                list_country_all_time.append(qs['location']['country_name'])

            list_times.append(qs['timestamp'])
            ft = date_ti.strptime(max(list_times)[:10], '%Y-%m-%d')
            if str(ft - time_delta) <= qs['timestamp'] < str(max(list_times)):  # 3 last month
                if 'asn' in qs.keys():
                    list_asn.append(qs['asn'])
                list_country.append(qs['location']['country_name'])

        dict_asn_3_month = dict(Counter(list_asn))
        dict_country_3_month = dict(Counter(list_country))

        # Use the count() method because it doesn't return results and doesn't require a paid API plan
        # And it also runs faster than doing a search(). data for all time
        result = api.count(query, facets=FACETS)
        print('Shodan Summary Information')
        print('Query: %s' % query)
        print('Total Results: %s\n' % result['total'])

        dict_country = {}
        dict_asn = {}
        # print(result)
        for term in result['facets']['country']:
            dict_country[term['value']] = term['count']

        for term in result['facets']['asn']:
            dict_asn[term['value']] = term['count']

    except Exception as e:
        print('Error: %s' % e)
        # sys.exit(1)

    return dict_country, dict_asn, dict_country_3_month, dict_asn_3_month, query


def get_data_censys_api():
    """
    Use Api Censys to get data(Country and ASN) for 3 last month
    """
    print('Censys Summary Information')
    CENSYS_API_ID = get_secret(section="CENSYS", setting="CENSYS_API_ID")
    CENSYS_API_SECRET = get_secret(section="CENSYS", setting="CENSYS_API_SECRET")
    h = CensysHosts(CENSYS_API_ID, CENSYS_API_SECRET)

    # Input validation
    if len(sys.argv) == 1:
        print('Usage: %s <search query>' % sys.argv[0])
        sys.exit(1)

    # Generate a query string out of the command-line arguments
    qs = ' '.join(sys.argv[1:])
    print('Query: %s' % qs)
    list_query = h.search(qs, at_time=date(2022, 4, 7), at_time_b=date(2022, 7, 7))  # list of dict  3 last month
    print('Total Results: %s\n' % len(list_query()))
    list_query = h.search(qs, at_time=date(2022, 4, 7), at_time_b=date(2022, 7, 7))  # list of dict

    list_country = []
    list_asn = []
    for query in list_query():
        list_country.append(query['location']['country'])
        list_asn.append(query['autonomous_system']['asn'])

    dict_country = dict(Counter(list_country))
    dict_asn = dict(Counter(list_asn))

    return dict_country, dict_asn, qs


def get_data_zoomeye_api():
    zm = zoomeye.ZoomEye()
    zm.username = get_secret(section="ZOOMEYE", setting="username")
    zm.password = get_secret(section="ZOOMEYE", setting="password")
    zm.login()

    # Input validation
    if len(sys.argv) == 1:
        print('Usage: %s <search query>' % sys.argv[0])
        sys.exit(1)

    # Generate a query string out of the command-line arguments
    query = ' '.join(sys.argv[1:])
    data = zm.dork_search(query)  #
    list_asn = []
    list_country_all_time = []
    list_country = []
    dt_lis = []
    list_asn_all_time = []
    time_delta = datetime.timedelta(days=90)

    for dt in data:
        # ASN and Country all time
        list_asn_all_time.append(dt['geoinfo']['asn'])
        list_country_all_time.append(dt['geoinfo']['country']['names']['en'])

        # get ASN and Country for 3 last month
        for dat in dt['whois'].values():
            dt_lis.append(dat['last_modified'])
            ft = date_ti.strptime(max(dt_lis)[:10], '%Y-%m-%d')
            if dat['last_modified'] >= str((ft - time_delta)):
                list_asn.append(dt['geoinfo']['asn'])
                list_country.append(dt['geoinfo']['country']['names']['en'])

    dic_country_3last_m = dict(Counter(list_country))
    dict_asn_3last_m = dict(Counter(list_asn))

    dict_asn_all_time = dict(Counter(list_asn_all_time))
    dict_country_all_time = dict(Counter(list_country_all_time))

    return dict_country_all_time, dict_asn_all_time, dic_country_3last_m, dict_asn_3last_m, query


def _graphik(data: dict, qs, label, title):
    names = list(data.keys())
    values = list(data.values())

    fig = plt.figure()
    fig.suptitle(title)

    plt.bar(range(len(data)), values, tick_label=names, align='center')
    plt.xticks(rotation=90)
    plt.xlabel(label)
    plt.text(14, 48, label)
    plt.title(qs)
    plt.show()


if __name__ == '__main__':
    # dict_country,dict_asn,query = get_data_censys_api()
    # _graphik(dict_country,query,"Country","Shodan Country  For Last 3 month")
    # _graphik(dict_asn,query,"ASN","Shodan ASN  For Last 3 month")

    # dict_country,dict_asn,dict_country_3_month,dict_asn_3_month,query = get_data_shodan_api()
    # _graphik(dict_country,query,"Country","Shodan Country For all time")
    # _graphik(dict_asn_3_month,query,"ASN","Shodan ASN  For All Time")

    dict_country, dict_asn, dict_country_3_month, dict_asn_3_month, query = get_data_zoomeye_api()
    _graphik(dict_country, query, "Country", "ZOOMEYE Country For all Time")
    # _graphik(dict_asn,query,"ASN","ZOOMEYE ASN For all Time")
