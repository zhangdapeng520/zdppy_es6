import os


def is_appengine():
    return is_local_appengine() or is_prod_appengine()


def is_appengine_sandbox():
    return is_appengine() and os.environ["APPENGINE_RUNTIME"] == "python27"


def is_local_appengine():
    return "APPENGINE_RUNTIME" in os.environ and os.environ.get(
        "SERVER_SOFTWARE", ""
    ).startswith("Development/")


def is_prod_appengine():
    return "APPENGINE_RUNTIME" in os.environ and os.environ.get(
        "SERVER_SOFTWARE", ""
    ).startswith("Google App Engine/")


def is_prod_appengine_mvms():
    """Deprecated."""
    return False
