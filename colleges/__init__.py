from colleges.sbcc import SBCC
from colleges.ucb import UCB
from colleges.ucsb import UCSB

__all__ = ["colleges", "college_names", "college_short_names", "get_user_college"]

colleges = [SBCC, UCSB, UCB]

college_names = [college.name for college in colleges]
college_short_names = [college.short_name for college in colleges]


def get_user_college(user):
    if user is None:
        return None
    for college in colleges:
        if college.short_name == user.college:
            return college
    return None
