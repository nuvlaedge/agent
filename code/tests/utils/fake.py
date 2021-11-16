#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import mock
import random
import kubernetes
from types import SimpleNamespace


def MockKubernetesEndpoint(name: str):
    endpoint = {
        'metadata': {
            'name': name
        },
        'subsets': [
            {
                'addresses': [
                    {
                        'ip': '172.17.0.52'
                    }
                ],
                'ports': [
                    {
                        'name': 'https',
                        'port': 6443,
                        'protocol': 'TCP'
                    }
                ]
            }
        ]
    }
    return json.loads(json.dumps(endpoint), object_hook=lambda d: SimpleNamespace(**d))


def base_pod(name: str=None, phase: str='running'):
    pod = {
        'metadata': {
            'namespace': 'namespace',
            'selfLink': random.randint(100, 999),
            'name': name if name else random.randint(100, 999)
        },
        'status': {
            'container_statuses': [
                {
                    'name': 'container1',
                    'ready': True,
                    'restart_count': 1,
                    'state': ''
                },
                {
                    'name': 'container2',
                    'ready': True,
                    'restart_count': 2,
                    'state': ''
                }
            ],
            'phase': phase
        }
    }
    return pod


def MockKubernetesPod(name: str=None, phase: str='running'):
    pod = json.loads(json.dumps(base_pod(name, phase)), object_hook=lambda d: SimpleNamespace(**d))
    # add 'state' after serialization cause k8s obj is not serializable
    for x in pod.status.container_statuses:
        x.state = kubernetes.client.V1ContainerState(waiting=True)
    return pod


def MockKubernetesPodMetrics(name: str=None, phase: str='running'):
    pod = base_pod(name, phase)
    pod['containers'] = [
        {
            'name': 'container1',
            'usage': {
                'cpu': '100n',
                'memory': '1Ki'
            }
        }
    ]
    return pod


def MockKubernetesDeployment():
    depl = {
        'spec': {
            'template': {
                'spec': {
                    'containers': [
                        {
                            'env': [{
                                'name': 'FOO',
                                'value': 'BAR'
                            }, {
                                'name': 'templated',
                                'value_from': 'template'
                            }
                            ]
                        }
                    ]
                }
            }
        }
    }
    return json.loads(json.dumps(depl), object_hook=lambda d: SimpleNamespace(**d))


def MockKubernetesNode(uid: str=None, ready: bool=True):
    node = {
        'status': {
            'node_info': {
                'os_image': 'FakeOS',
                'kernel_version': 'fake kernel v0',
                'architecture': 'arm',
                'kubelet_version': 'v1'
            },
            'conditions': [{'last_heartbeat_time': 'time',
                            'last_transition_time': 'time',
                            'message': 'Flannel is running on this node',
                            'reason': 'FlannelIsUp',
                            'status': 'False',
                            'type': 'NetworkUnavailable'},
                           {'last_heartbeat_time': 'time',
                            'last_transition_time': 'time',
                            'message': 'kubelet is posting ready status. AppArmor enabled',
                            'reason': 'KubeletReady',
                            'status': 'True' if ready else 'False',
                            'type': 'Ready'}]
        },
        'metadata': {
            'name': f'{uid} NAME' if uid else random.randint(100, 999),
            'uid': uid if uid else random.randint(100, 999),
            'labels': [],
            'cluster_name': None
        }
    }

    return json.loads(json.dumps(node), object_hook=lambda d: SimpleNamespace(**d))


class Fake(object):
    """Create Mock()ed methods that match another class's methods."""

    @classmethod
    def imitate(cls, *others):
        for other in others:
            for name in other.__dict__:
                try:
                    setattr(cls, name, mock.Mock())
                except (TypeError, AttributeError):
                    pass
        return cls


class MockContainer(object):
    def __init__(self, status='paused', myid=None):
        self.status = status
        self.name = random.randint(100, 999)
        self.id = random.randint(100, 999) if not myid else myid
        self.labels = {
            'com.docker.compose.project.working_dir': '/workdir',
            'com.docker.compose.project.config_files': 'a.yml,b.yml',
            'com.docker.compose.project': 'nuvlabox'
        }
        self.attrs = {
            'Config': {
                'Image': 'fake-image'
            },
            'NetworkSettings': {
                'Networks': {
                    'fake-network': {}
                }
            },
            'RestartCount': 1
        }

    def remove(self):
        pass

    def kill(self):
        pass


class MockDockerNode(object):
    def __init__(self, state: str='ready'):
        self.attrs = {
            'Status': {
                'State': state
            }
        }
        self.id = random.randint(100, 999)


class FakeRequestsResponse(object):
    def __init__(self, **kwargs):
        self.status_code = kwargs.get('status_code') if kwargs.get('status_code') else 123
        self.json_response = kwargs.get('json_response') if kwargs.get('json_response') else {'req': 'fake response'}

    def json(self):
        return self.json_response


class FakeNuvlaApi(object):
    """ Fake the nuvla.api module """
    def __init__(self, reference_api_keys, **kwargs):
        self.api_keys = reference_api_keys
        self.kwargs = kwargs
        self.MockResponse = self.Response(self.kwargs.get('id', 'fake/id'), self.kwargs.get('data', {}))

    class Response(object):
        def __init__(self, id, data):
            self.data = {**{'id': id}, **data}

    def _cimi_post(self, _):
        return self.api_keys

    def get(self, id, **kwargs):
        return self.Response(id, self.kwargs.get('data', {}))

    def edit(self, nuvlabox_id, payload):
        return self.MockResponse

    def delete(self, nuvlabox_id):
        return self.MockResponse

    def add(self, resource, _):
        return self.MockResponse

    def login_apikey(self, key, secret):
        return self.MockResponse
