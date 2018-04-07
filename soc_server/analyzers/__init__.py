import requests


class Status(object):
    GREEN_VAL = 0  # No malicious activity detected
    WHITE_VAL = None  # Unknown value, something went wrong

    class _Color(object):
        def __init__(self, val):
            self.val = val
            self.name = "Color"

        def __str__(self):
            return self.name

    class Red(_Color):  # Result is negative
        def __init__(self, val):
            super(Status.Red, self).__init__(val)
            self.name = "RED"

    class Green(_Color):  # Result is positive
        def __init__(self):
            super(Status.Green, self).__init__(Status.GREEN_VAL)
            self.name = "GREEN"

    class White(_Color):  # Result is unknown/needs user interaction
        def __init__(self):
            super(Status.White, self).__init__(Status.WHITE_VAL)
            self.name = "WHITE"

    class Amber(_Color):  # Result couldn't be obtained
        def __init__(self, val):
            super(Status.Amber, self).__init__(val)
            self.name = "AMBER"


class BaseAnalyzer(object):
    def __init__(self):
        self.session = requests.Session()

    # Error-handled function to make any calls with requests
    def request(self, method, url, **kwargs):
        response = self.session.request(method, url, **kwargs)
        response.raise_for_status()
        return response

    # Returns a Tuple of (Status, val)
    # Where val is a given value of "how malicious" determined per analyzer [0-1]
    def analyze(self, packet):
        raise NotImplementedError("Can't use BaseAnalyzer!")
