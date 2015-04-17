# -*- coding: utf-8 -*-

import os

def check_and_create_dir(dir):
    """
    If the directory where the certificates and keys are stored doesn't exist, then create it.
    """
    if not os.path.exists(dir):
        os.makedirs(dir)


def exists_and_isfile(path):
    return os.path.exists(path) and os.path.isfile(path)
