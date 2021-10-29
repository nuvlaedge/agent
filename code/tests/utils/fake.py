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


class FakeNuvlaApi(object):
    """ Fake the nuvla.api module """
    def __init__(self, reference_api_keys, **kwargs):
        self.api_keys = reference_api_keys
        self.kwargs = kwargs

    class Response(object):
        def __init__(self, nb_id, data):
            self.data = {**{'id': nb_id}, **data}

    def _cimi_post(self, _):
        return self.api_keys

    def get(self, nuvlabox_id, **kwargs):
        return self.Response(nuvlabox_id, self.kwargs.get('data', {}))

    # def edit(self, nuvlabox_id, payload):
    #     return

    def add(self, resource, _):
        return self.Response(resource, self.kwargs.get('data', {}))
