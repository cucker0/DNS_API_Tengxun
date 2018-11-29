#!/usr/bin/env python
# -*- coding:utf-8 -*-

# 腾讯 云解析DNS API
# API文档 https://cloud.tencent.com/document/api/302/4032

import hashlib
import requests
import hmac
import random
import time
import base64
import json


class Sign(object):
    def __init__(self, secretKey):
        self.secretKey = secretKey

    # 生成签名串
    def make(self, requestHost, requestUri, params, method='GET'):
        srcStr = method.upper() + requestHost + requestUri + '?' + "&".join(k.replace("_", ".") + "=" + str(params[k]) for k in sorted(params.keys()))
        hashed = hmac.new(bytes(self.secretKey, 'utf8'), bytes(srcStr, 'utf8'), hashlib.sha1)
        return base64.b64encode(hashed.digest())

class DnsHelper(object):
    """
    DNS 相关操作类
    ## API密钥管理 https://console.cloud.tencent.com/cam/capi
    """
    SecretId = 'xxxXTG66xxxUMF6xxxhfmEmzxxxmAOYe2'
    SecretKey = 'xxxacLw2MzxxxC773rxxxus8kxxx'
    requestHost = 'cns.api.qcloud.com'
    requestUri = '/v2/index.php'

    def __init__(self):
        self.params = {
            'Timestamp': int(time.time()),
            'SecretId': self.SecretId,
            'Nonce': random.randint(10000000, 99999999),
        }
        self.url = 'https://%s%s' % (DnsHelper.requestHost, DnsHelper.requestUri)

    def get_domain_list(self, offset=0, length=20, keyword='', qProjectId=''):
        """
        获取域名列表
        :param offset: 偏移量，默认为0。关于offset的更进一步介绍参考 API 简介中的相关小节。
        :param length:返回数量，默认 20，最大值 100。关于limit的更进一步介绍参考 API 简介中的相关小节。
        :param keyword:（过滤条件）根据关键字搜索域名
        :param qProjectId:（过滤条件）项目ID
        :return: 域名列表
        """
        self.params['Action'] = 'DomainList'
        self.params['offset'] = offset
        self.params['length'] = length
        self.params['keyword'] = keyword
        if qProjectId :
            self.params['qProjectId'] = qProjectId
        self.params['Signature'] = Sign(self.SecretKey).make(self.requestHost,self.requestUri, self.params)

        ret = requests.get(self.url, params=self.params)
        return json.loads(ret.text)

    def add_domain(self, domain, projectId=''):
        """
        添加域名
        :param domain:要添加的域名（主域名，不包括 www，例如：qcloud.com）
        :param projectId:项目ID，如果不填写，则为“默认项目”
        :return:
        """
        self.params['Action'] = 'DomainCreate'
        self.params['domain'] = domain
        if projectId :
            self.params['projectId'] = projectId
        self.params['Signature'] = Sign(self.SecretKey).make(self.requestHost, self.requestUri,self.params)

        ret = requests.get(self.url, params=self.params)
        return json.loads(ret.text)

    def set_domain_status(self, domain, status):
        """
        设置域名状态
        :param domain:要操作的域名（主域名，不包括 www，例如：qcloud.com）
        :param status:可选值为：'disable' 和 'enable'，分别代表暂停、启用
        :return:
        """
        self.params['Action'] = 'SetDomainStatus'
        self.params['domain'] = domain
        self.params['status'] = status
        self.params['Signature'] = Sign(self.SecretKey).make(self.requestHost, self.requestUri,self.params)
        ret = requests.get(self.url, params=self.params)
        return json.loads(ret.text)

    def delete_domain(self, domain):
        """
        删除域名
        :param domain: 要删除的域名
        :return:
        """
        self.params['Action'] = 'DomainDelete'
        self.params['domain'] = domain

        self.params['Signature'] = Sign(self.SecretKey).make(self.requestHost, self.requestUri,self.params)
        ret = requests.get(self.url, params=self.params)
        return json.loads(ret.text)


    def get_record_list(self, domain_name, offset=0, length=20, subDomain='', recordType='', qProjectId=0):
        """
        获取解析记录列表
        :param domain_name: 要操作的域名（主域名，不包括 www，例如：qcloud.com）
        :param offset:int类型，偏移量，默认为0。关于offset的更进一步介绍参考 API 简介中的相关小节。
        :param length:int类型，返回数量，默认 20，最大值 100。关于limit的更进一步介绍参考 API 简介中的相关小节。
        :param subDomain:（过滤条件）根据子域名进行过滤
        :param recordType:（过滤条件）根据记录类型进行过滤
        :param qProjectId:（过滤条件）项目ID, int类型
        :return:
        """
        self.params['Action'] = 'RecordList'
        self.params['domain'] = domain_name
        self.params['offset'] = offset
        self.params['length'] = length
        self.params['subDomain'] = subDomain
        self.params['recordType'] = recordType
        if qProjectId:
            self.params['qProjectId'] = qProjectId

        self.params['Signature'] = Sign(self.SecretKey).make(self.requestHost, self.requestUri,self.params)
        ret = requests.get(self.url, params=self.params)
        return json.loads(ret.text)

    def add_record(self, domain, subDomain, recordType, value, recordLine='默认', ttl=600, mx=1):
        """
        添加解析记录
        :param domain:要添加解析记录的域名（主域名，不包括 www，例如：qcloud.com）
        :param subDomain:子域名，例如：www
        :param recordType:记录类型，可选的记录类型为："A", "CNAME", "MX", "TXT", "NS", "AAAA", "SRV"
        :param value:记录值, 如 IP:192.168.10.2, CNAME: cname.dnspod.com., MX: mail.dnspod.com.
        :param recordLine:记录的线路名称，如："默认"
        :param ttl:TTL 值，范围1-604800，不同等级域名最小值不同，默认为 600
        :param mx:MX优先级，范围为 0~50，当记录类型为 MX 时必选
        :return:
        """
        self.params['Action'] = 'RecordCreate'
        self.params['domain'] =domain
        self.params['subDomain'] = subDomain
        self.params['recordType'] = recordType
        self.params['value'] = value
        self.params['recordLine'] = recordLine
        self.params['ttl'] = ttl
        if recordType.upper() == 'MX':
            self.params['mx'] = mx
        self.params['Signature'] = Sign(self.SecretKey).make(self.requestHost, self.requestUri,self.params)

        ret = requests.get(self.url, params=self.params)
        return json.loads(ret.text)

    def update_record_status(self, domain, recordId, status):
        """
        设置解析记录状态
        :param domain:解析记录所在的域名
        :param recordId:解析记录ID，int类型
        :param status:可选值为：'disable' 和 'enable'，分别代表暂停、启用
        :return:
        """
        self.params['Action'] = 'RecordStatus'
        self.params['domain'] = domain
        self.params['recordId'] = recordId
        self.params['status'] = status
        self.params['Signature'] = Sign(self.SecretKey).make(self.requestHost, self.requestUri,self.params)

        ret = requests.get(self.url, params=self.params)
        return json.loads(ret.text)

    def update_record(self, domain, recordId, subDomain, recordType, value, recordLine='默认', ttl=600, mx=1):
        """
        修改解析记录
        :param domain: 要操作的域名（主域名，不包括 www，例如：qcloud.com）
        :param recordId: int类型，解析记录的ID，可通过RecordList接口返回值中的 id 获取
        :param subDomain: 子域名，例如：www
        :param recordType: 记录类型，可选的记录类型为："A", "CNAME", "MX", "TXT", "NS", "AAAA", "SRV"
        :param value:记录值, 如 IP:192.168.10.2, CNAME: cname.dnspod.com., MX: mail.dnspod.com.
        :param recordLine: 记录的线路名称，如："默认"
        :param ttl: TTL 值，范围1-604800，不同等级域名最小值不同，默认为 600， int类型
        :param mx: MX优先级，范围为 0~50，当记录类型为 MX 时必选， int类型
        :return:
        """
        self.params['Action'] = 'RecordModify'
        self.params['domain'] = domain
        self.params['recordId'] = recordId
        self.params['subDomain'] = subDomain
        self.params['recordType'] = recordType
        self.params['value'] = value
        self.params['recordLine'] = recordLine
        self.params['ttl'] = ttl
        if recordType.upper() == 'MX':
            self.params['mx'] = mx
        self.params['Signature'] = Sign(self.SecretKey).make(self.requestHost, self.requestUri,self.params)

        ret = requests.get(self.url, params=self.params)
        return json.loads(ret.text)

    def delete_record(self, domain, recordId):
        """
        删除解析记录
        :param domain:解析记录所在的域名
        :param recordId:int类型，解析记录ID
        :return:
        """
        self.params['Action'] = 'RecordDelete'
        self.params['domain'] = domain
        self.params['recordId'] = recordId
        self.params['Signature'] = Sign(self.SecretKey).make(self.requestHost, self.requestUri,self.params)

        ret = requests.get(self.url, params=self.params)
        return json.loads(ret.text)


if __name__ == '__main__':
    domains = DnsHelper().get_domain_list()

    for domain in domains['data']['domains']:
        total = 0
        lenght = 100
        records = DnsHelper().get_record_list(domain['name'], total, lenght)
        # records = json.loads(records)

        while total < int(records['data']['info']['record_total'] ) - lenght:

            total += lenght
            records_tmp = DnsHelper().get_record_list(domain['name'], total, lenght)
            records['data']['records'].extend(records_tmp['data']['records'])

        domain_name = records['data']['domain']['name']
        print("")
        print(domain_name, len( records['data']['records']) )
        print("")
        print(records)
        ## 打印record
        # for r in records['data']['records']:
        #     # r['status']          相当于域名是否可用
        #     print('name:%s.%s    type:%s    value:%s    enabled:%s   status:%s'  %(r['name'], domain_name, r['type'], r['value'], r['enabled'], r['status']) )

    ## 添加record记录
    # a_record = {'domain':'xx.com', 'subDomain':'tengxuntest2', 'recordType':'A', 'value':'8.8.8.8'}
    # print(DnsHelper().add_record(**a_record))

    ## 更新record状态
    # a_record = {'domain': 'xx.com', 'recordId':393860438, 'status':'disable'}
    # print(DnsHelper().update_record_status(**a_record))

    ## 删除record记录
    a_record = { 'domain': 'xx.com', 'recordId':393861002 }
    DnsHelper().delete_record(**a_record)
