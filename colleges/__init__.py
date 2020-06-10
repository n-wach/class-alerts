import importlib
import logging

__all__ = ["colleges", "college_names", "college_short_names", "get_user_college"]
logger = logging.getLogger("app.colleges")

college_modules = [
    ("sbcc", "SBCC"),
    ("ucb", "UCB"),
    ("vcc", "VCC"),
    ("calpoly_slo", "CalpolySLO"),
    ("ucsd", "UCSD"),
    ("ucsb", "UCSB"),
    ("ucla", "UCLA"),
]

colleges = []

for module_name, class_name in college_modules:
    try:
        module = importlib.import_module("colleges.{}".format(module_name), "colleges")
        colleges.append(getattr(module, class_name))
    except Exception as e:
        logger.exception("Error loading college: {}".format(module_name))

college_names = [college.name for college in colleges]
college_short_names = [college.short_name for college in colleges]


def get_user_college(user):
    if user is None:
        return None
    for college in colleges:
        if college.short_name == user.college:
            return college
    return None
