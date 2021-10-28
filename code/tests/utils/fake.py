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
