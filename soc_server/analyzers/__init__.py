import requests


class Status(object):
    RED_NAME = "RED"
    GREEN_NAME = "GREEN"
    WHITE_NAME = "WHITE"
    AMBER_NAME = "AMBER"

    GREEN_VAL = 0  # No malicious activity detected
    WHITE_VAL = -1  # Unknown value, something went wrong
    AMBER_VAL = 1
    RED_VAL = 5

    MAPPING = {
        WHITE_NAME: WHITE_VAL,
        GREEN_NAME: GREEN_VAL,
        AMBER_NAME: AMBER_VAL,
        RED_NAME: RED_VAL
    }

    THRESHOLDS = {
        **{i: "GREEN" for i in range(0, 3)},
        **{i: "AMBER" for i in range(3, 7)},
        **{i: "RED" for i in range(7, 11)}
    }

    @staticmethod
    def get_status(status_list):
        score = sum([Status.MAPPING[s.name]/len(status_list)*10 for s in status_list])
        if score < 0:
            return Status.WHITE_NAME
        return Status.THRESHOLDS.get(score, Status.RED_NAME)  # Get value, if threshold isn't in dict, it's red

    class _Color(object):
        def __init__(self, name, val):
            self.val = val
            self.name = name

        def __str__(self):
            return self.name

    class Red(_Color):  # Result is negative
        def __init__(self, val=1):
            super(Status.Red, self).__init__(Status.RED_NAME, val)

    class Green(_Color):  # Result is positive
        def __init__(self):
            super(Status.Green, self).__init__(Status.GREEN_NAME, Status.GREEN_VAL)

    class White(_Color):  # Result is unknown/needs user interaction
        def __init__(self):
            super(Status.White, self).__init__(Status.WHITE_NAME, Status.WHITE_VAL)

    class Amber(_Color):  # Result couldn't be obtained
        def __init__(self, val=0.5):
            super(Status.Amber, self).__init__(Status.AMBER_NAME, val)


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
