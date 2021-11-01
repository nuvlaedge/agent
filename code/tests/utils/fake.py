#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import mock


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
